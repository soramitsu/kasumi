//! A level is a file of bounded frozen-run pieces under an authenticated binary tree.
//! Every child points backward, and opening a level needs only its root handle.
use crate::{MAX_KEY, invalid, live_bulk_filter::BulkFilter, take};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

const MAGIC: &[u8; 8] = b"KSLVLV01";
const FOOTER: usize = 8 + 48;
const NODE_MAX: usize = 2 * MAX_KEY + 2 * 48 + 6;
pub(super) const HEIGHT: usize = u64::BITS as usize;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Link {
    pub at: u64,
    pub len: u64,
    pub root: [u8; 32],
}
impl Link {
    fn encode(self, out: &mut Vec<u8>) {
        out.extend(self.at.to_le_bytes());
        out.extend(self.len.to_le_bytes());
        out.extend(self.root);
    }
    fn decode(input: &mut &[u8], before: u64) -> io::Result<Self> {
        let at = u64::from_le_bytes(take(input, 8)?.try_into().unwrap());
        let len = u64::from_le_bytes(take(input, 8)?.try_into().unwrap());
        let root = take(input, 32)?.try_into().unwrap();
        if len == 0 || at.checked_add(len).is_none_or(|end| end > before) {
            return Err(invalid("invalid live level extent"));
        }
        Ok(Self { at, len, root })
    }
}
#[derive(Clone)]
pub(super) struct Leaf {
    pub first: Vec<u8>,
    pub last: Vec<u8>,
    pub rows: Link,
    pub deleted: Option<Link>,
}

pub(super) enum Node {
    Leaf(Leaf),
    Branch {
        split: Vec<u8>,
        left: Link,
        right: Link,
    },
    BulkRoot {
        tree: Link,
        filter: Link,
    },
}
fn get_key(input: &mut &[u8]) -> io::Result<Vec<u8>> {
    let n = crate::u16_from(input)?;
    if n > MAX_KEY {
        return Err(invalid("invalid live level key length"));
    }
    Ok(take(input, n)?.to_vec())
}
fn put_key(out: &mut Vec<u8>, key: &[u8]) {
    out.extend((key.len() as u16).to_le_bytes());
    out.extend(key);
}
pub(super) fn read(file: &mut File, link: Link) -> io::Result<Node> {
    if link.len > NODE_MAX as u64 {
        return Err(invalid("oversized live level node"));
    }
    file.seek(SeekFrom::Start(link.at))?;
    let mut bytes = vec![0; link.len as usize];
    file.read_exact(&mut bytes)?;
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != link.root {
        return Err(invalid("live level node digest differs"));
    }
    let mut input = bytes.as_slice();
    let node = match take(&mut input, 1)?[0] {
        0 => {
            let first = get_key(&mut input)?;
            let last = get_key(&mut input)?;
            if first > last {
                return Err(invalid("unordered live level piece"));
            }
            let rows = Link::decode(&mut input, link.at)?;
            let deleted = if input.is_empty() {
                None
            } else {
                let range = Link::decode(&mut input, link.at)?;
                if range.at < rows.at + rows.len {
                    return Err(invalid("overlapping live level pieces"));
                }
                Some(range)
            };
            Node::Leaf(Leaf {
                first,
                last,
                rows,
                deleted,
            })
        }
        1 => Node::Branch {
            split: get_key(&mut input)?,
            left: Link::decode(&mut input, link.at)?,
            right: Link::decode(&mut input, link.at)?,
        },
        2 => {
            let tree = Link::decode(&mut input, link.at)?;
            let filter = Link::decode(&mut input, link.at)?;
            if tree.at + tree.len != filter.at || filter.at + filter.len != link.at {
                return Err(invalid("invalid bulk membership extents"));
            }
            Node::BulkRoot { tree, filter }
        }
        _ => return Err(invalid("invalid live level node tag")),
    };
    if !input.is_empty() {
        return Err(invalid("trailing live level node fields"));
    }
    Ok(node)
}

pub(super) fn read_filter(file: &mut File, link: Link) -> io::Result<BulkFilter> {
    let size = usize::try_from(link.len).map_err(|_| invalid("bulk filter length overflow"))?;
    let mut filter = BulkFilter::with_bytes(size)?;
    file.seek(SeekFrom::Start(link.at))?;
    file.read_exact(filter.bytes_mut())?;
    if <[u8; 32]>::from(Sha256::digest(filter.bytes())) != link.root {
        return Err(invalid("bulk membership filter digest differs"));
    }
    Ok(filter)
}
pub(super) fn open(file: &mut File, expected: [u8; 32]) -> io::Result<Option<Link>> {
    let len = file.metadata()?.len();
    if len < FOOTER as u64 {
        return Err(invalid("truncated live level footer"));
    }
    file.seek(SeekFrom::End(-(FOOTER as i64)))?;
    let mut bytes = [0; FOOTER];
    file.read_exact(&mut bytes)?;
    if &bytes[..8] != MAGIC || <[u8; 32]>::from(Sha256::digest(bytes)) != expected {
        return Err(invalid("live level footer digest differs"));
    }
    if bytes[8..] == [0; 48] {
        if len != FOOTER as u64 {
            return Err(invalid("empty live level contains data"));
        }
        return Ok(None);
    }
    let root = Link::decode(&mut &bytes[8..], len - FOOTER as u64)?;
    if root.at + root.len != len - FOOTER as u64 {
        return Err(invalid("live level root extent differs"));
    }
    Ok(Some(root))
}

struct Subtree {
    first: Vec<u8>,
    link: Link,
}
fn append(file: &mut File, bytes: &[u8]) -> io::Result<Link> {
    let at = file.stream_position()?;
    file.write_all(bytes)?;
    Ok(Link {
        at,
        len: bytes.len() as u64,
        root: Sha256::digest(bytes).into(),
    })
}
fn join(file: &mut File, left: Subtree, right: Subtree) -> io::Result<Subtree> {
    let mut bytes = vec![1];
    put_key(&mut bytes, &right.first);
    left.link.encode(&mut bytes);
    right.link.encode(&mut bytes);
    Ok(Subtree {
        first: left.first,
        link: append(file, &bytes)?,
    })
}

#[derive(Default)]
pub(super) struct Builder {
    heights: Vec<Option<Subtree>>,
}
impl Builder {
    pub fn push(&mut self, file: &mut File, leaf: Leaf) -> io::Result<()> {
        let mut bytes = vec![0];
        put_key(&mut bytes, &leaf.first);
        put_key(&mut bytes, &leaf.last);
        leaf.rows.encode(&mut bytes);
        if let Some(deleted) = leaf.deleted {
            deleted.encode(&mut bytes);
        }
        let mut tree = Subtree {
            first: leaf.first,
            link: append(file, &bytes)?,
        };
        for slot in &mut self.heights {
            let Some(left) = slot.take() else {
                *slot = Some(tree);
                return Ok(());
            };
            tree = join(file, left, tree)?;
        }
        self.heights.push(Some(tree));
        Ok(())
    }
    pub fn finish(self, file: &mut File, filter: Option<&BulkFilter>) -> io::Result<[u8; 32]> {
        let mut tree = None;
        for older in self.heights.into_iter().flatten() {
            tree = Some(match tree {
                None => older,
                Some(newer) => join(file, older, newer)?,
            });
        }
        let mut footer = Vec::from(MAGIC.as_slice());
        if let Some(root) = tree {
            let mut link = root.link;
            if let Some(filter) = filter {
                let membership = append(file, filter.bytes())?;
                let mut node = vec![2];
                link.encode(&mut node);
                membership.encode(&mut node);
                link = append(file, &node)?;
            }
            link.encode(&mut footer);
        } else {
            footer.resize(FOOTER, 0);
        }
        file.write_all(&footer)?;
        Ok(Sha256::digest(&footer).into())
    }
}
