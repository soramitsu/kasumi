//! Real frontier/page framing fixture only. Sharing one actual Archived DTO
//! between generated IDs deliberately skips CollectionRecords, row validation,
//! accepted-generation completeness and hydration. Every page is staged by the
//! production Resources::push/flush/finish_pages code under its actual grant.
use super::*;

pub(crate) const WIDTH: usize = tree::MAX_ID_BYTES;
pub(crate) const PER_PAGE: usize =
    (tree::PAGE_BYTES - tree::HEADER_BYTES) / (2 + WIDTH + tree::DESCRIPTOR_BYTES);
pub(crate) const ROWS: usize = PER_PAGE * (PER_PAGE + 1) + 1;

pub(crate) fn id(index: usize) -> [u8; WIDTH] {
    assert!(index < 10_000);
    let mut bytes = [b'x'; WIDTH];
    let mut suffix = index;
    for digit in bytes[WIDTH - 4..].iter_mut().rev() {
        *digit = b'0' + (suffix % 10) as u8;
        suffix /= 10;
    }
    bytes
}

pub(crate) struct Framing {
    pub(crate) tree: [u8; 16],
    pub(crate) object: OverflowRef,
    pub(crate) root: Root,
    pub(crate) collapsed: Root,
    pub(crate) semantic_bytes: u64,
    pub(crate) totals: Totals,
    pub(crate) objects_before_collapse: u64,
    pub(crate) objects_after_collapse: u64,
}

pub(crate) fn stage<'guard, 'engine>(
    stage: PrimaryStage<'guard, 'engine>,
    archived: &ArchivedDocument,
) -> Result<(PrimaryStage<'guard, 'engine>, Framing)> {
    let mut resources = Resources {
        stage: Some(stage),
        frontier: Frontier {
            levels: Vec::new(),
            reservation: None,
        },
        tree: [0; 16],
        generation: 1,
        last: Name::EMPTY,
        expected: Totals::default(),
    };
    resources.allocate()?;
    let object = resources.dto(CanonicalDto::Archived(archived), &mut || Ok(()))?;
    let first = id(0);
    let semantic_bytes = codec(tree::archived_metadata_bytes(
        std::str::from_utf8(&first)?,
        object.encoded_bytes,
    ))?;
    // Fixed-width, unescaped ASCII IDs all have the same map-entry byte quote.
    for index in 0..ROWS {
        let bytes = id(index);
        let name = Name::new(std::str::from_utf8(&bytes)?)?;
        resources.expected = codec(resources.expected.add(Totals {
            archived_count: 1,
            archived_metadata_bytes: semantic_bytes,
            ..Totals::default()
        }))?;
        resources.push(
            0,
            Slot {
                name,
                value: Value::Leaf(Leaf {
                    version: archived.version,
                    kind: RecordKind::Archived,
                    object,
                    semantic_bytes,
                }),
            },
            &mut || Ok(()),
        )?;
    }
    assert_eq!(PER_PAGE, 47);
    assert_eq!(ROWS, 2257);
    // The last insertion itself spills a full leaf into a full level-1 page,
    // recursively carrying that actual interior page into level 2. This is
    // checked before finish_pages can supply a carry of its own.
    assert_eq!(resources.frontier.levels[0].len, 1);
    assert_eq!(resources.frontier.levels[1].len, 1);
    assert_eq!(resources.frontier.levels[2].len, 1);
    assert!(
        resources.frontier.levels[3..]
            .iter()
            .all(|level| level.len == 0)
    );
    let Value::Child(carried) = resources.frontier.levels[2].slots[0].value else {
        panic!("actual interior carry absent")
    };
    assert_eq!(carried.totals.archived_count, (PER_PAGE * PER_PAGE) as u64);

    let root = resources
        .finish_pages(&mut || Ok(()))?
        .context("framing root absent")?;
    assert_eq!(root.level, 2);
    assert!(resources.frontier.levels.iter().all(|level| level.len == 0));
    let objects_before_collapse = resources
        .stage
        .as_ref()
        .unwrap()
        .resources
        .attempt
        .unwrap()
        .next_object;
    // Supply an actual already-staged final root as the sole carried child.
    // The finalizer must return its exact descriptor, without another page.
    resources.push(
        usize::from(root.level) + 1,
        Slot {
            name: Name::new(std::str::from_utf8(&first)?)?,
            value: Value::Child(Child {
                reference: root.reference,
                totals: resources.expected,
            }),
        },
        &mut || Ok(()),
    )?;
    let collapsed = resources
        .finish_pages(&mut || Ok(()))?
        .context("collapsed framing root absent")?;
    let objects_after_collapse = resources
        .stage
        .as_ref()
        .unwrap()
        .resources
        .attempt
        .unwrap()
        .next_object;
    assert_eq!(collapsed, root);
    assert_eq!(objects_after_collapse, objects_before_collapse);
    assert!(resources.frontier.levels.iter().all(|level| level.len == 0));
    let framing = Framing {
        tree: resources.tree,
        object,
        root,
        collapsed,
        semantic_bytes,
        totals: resources.expected,
        objects_before_collapse,
        objects_after_collapse,
    };
    let stage = resources.stage.take().unwrap();
    drop(resources);
    Ok((stage, framing))
}
