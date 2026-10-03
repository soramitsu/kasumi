//! Default URL parse heap only, not the surrounding topology/decode operation.
//!
//! Pinned sources: Rust 1.97.1 (8bab26f4f68e0e26f0bb7960be334d5b520ea452),
//! url 2.5.8, idna 1.1.0, idna_adapter 1.2.2, ICU normalizer 2.3.0 and
//! smallvec 1.16.0. Requalify on changes to those versions or allocator policy.
//!
//! This sums overlapping and mutually exclusive buffers conservatively. Each
//! backing allocation is rounded to a power of two with 64 bytes of allocator
//! policy overhead, as used by other Kasumi typed quotes. Growth includes the
//! old and new allocation simultaneously. This is not an exact RSS bound.
use crate::{Error, ErrorCode, Result};

// ICU decomposing_next uses 4 length bits plus2 (<=17), with an explicit
// FDFA18-scalar case. Hangul produces<=3 and special non-starters<=2.
const MAX_DECOMPOSED_SCALARS: u64 = 18;
// Punycode uses u32 delta, BASE36 and T_MAX26: each continuation divides the
// remainder by at least10. Ten continuations plus one last digit cover u32.
const MAX_PUNYCODE_DIGITS: u64 = 11;
const PUNYCODE_DECODE_INPUT: u64 = 2000;
const ALLOCATION_OVERHEAD: u64 = 64;

fn overflow() -> Error {
    Error::new(ErrorCode::QuotaExceeded, "endpoint workspace size overflow")
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or_else(overflow)
}
fn backing(bytes: u64) -> Result<u64> {
    if bytes == 0 {
        return Ok(0);
    }
    if bytes > isize::MAX as u64 {
        return Err(overflow());
    }
    add(
        bytes.checked_next_power_of_two().ok_or_else(overflow)?,
        ALLOCATION_OVERHEAD,
    )
}

// Rust RawVec grows max(2*old, required, min_non_zero), so when every requested
// lower bound fits `items`, capacity<=max(2*items,min_non_zero). SmallVec's
// next-power-of-two growth is bounded by the same expression. Iterators on the
// quoted paths have sound lower bounds and none reserves a speculative upper
// bound exceeding the component limits below. Both allocations cover realloc.
fn growing(items: u64, width: u64, inline: u64) -> Result<u64> {
    if items <= inline {
        return Ok(0);
    }
    let minimum = if width == 1 { 8 } else { 4 };
    let capacity = mul(items, 2)?.max(minimum);
    mul(backing(mul(capacity, width)?)?, 2)
}

fn sort_scratch(items: u64, width: u64) -> Result<u64> {
    // Exact upper branch from pinned stable/driftsort_main. It also covers
    // size-optimized mergesort's floor(n/2) scratch. For small arrays the bound
    // fits the4096-byte stack storage, so no heap is quoted.
    let scratch = (items - items / 2)
        .max(items.min(8_000_000 / width))
        .max(48); // SMALL_SORT_GENERAL_THRESHOLD32 +16
    if scratch <= 4096 / width {
        return Ok(0);
    }
    backing(mul(scratch, width)?)
}

// Extract only the WHATWG special-scheme host path whose parser branch is
// explicit in pinned url::parser. Other inputs use the whole input as an upper
// bound. This does not validate or normalize the URL, and does not allocate.
fn special_host(endpoint: &str) -> Option<&str> {
    let (scheme, tail) = endpoint.split_once(':')?;
    if !["http", "https", "ws", "wss", "ftp"]
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s))
    {
        return None;
    }
    // Input's iterator ignores tab/newline everywhere. The special-authority
    // branch consumes any number of forward/backward slashes after the colon.
    let tail = tail.trim_start_matches(['/', '\\', '\t', '\r', '\n']);
    let end = tail.find(['/', '\\', '?', '#']).unwrap_or(tail.len());
    let authority = &tail[..end];
    // parse_userinfo uses the last literal @; percent-encoded @ is not a delimiter.
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let mut bracketed = false;
    for (index, byte) in host_port.bytes().enumerate() {
        match byte {
            b'[' => bracketed = true,
            b']' => bracketed = false,
            b':' if !bracketed => return Some(&host_port[..index]),
            _ => {}
        }
    }
    Some(host_port)
}

// A sufficient condition for IDNA passthrough, never host validation. It
// matches the pinned fast-label predicate, deliberately excluding numeric and
// ACE labels, percent escapes, ignored controls and all Unicode spellings.
fn ascii_passthrough_host(host: &str) -> bool {
    host.split('.').all(|label| {
        let bytes = label.as_bytes();
        matches!(bytes.first(), Some(b'a'..=b'z'))
            && bytes.last() != Some(&b'-')
            && !(bytes.len() >= 4 && bytes[2..4] == *b"--")
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    })
}

#[derive(Clone, Copy)]
enum HostPath {
    Unclassified,
    Ascii,
    AsciiAce,
}
fn host_path(host: &str) -> HostPath {
    if !host.is_ascii()
        || host
            .bytes()
            .any(|b| matches!(b, b'%' | b'\t' | b'\r' | b'\n'))
    {
        return HostPath::Unclassified;
    }
    if host.split('.').any(|label| {
        label
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("xn--"))
    }) {
        HostPath::AsciiAce
    } else {
        HostPath::Ascii
    }
}

pub(super) fn quote(endpoint: &str) -> Result<u64> {
    let n = u64::try_from(endpoint.len()).map_err(|_| overflow())?;
    if n == 0 {
        return Ok(0);
    }
    if let Some(host) = special_host(endpoint) {
        if host.is_empty() || ascii_passthrough_host(host) {
            // Only serialization remains. Userinfo/path/query/fragment may
            // percent-expand each original byte by3; syntax adds at most8.
            return growing(add(mul(n, 3)?, 8)?, 1, 0);
        }
        let host_len = u64::try_from(host.len()).map_err(|_| overflow())?;
        let labels =
            u64::try_from(host.bytes().filter(|b| *b == b'.').count()).map_err(|_| overflow())?;
        return general_quote(n, host_len, add(labels, 1)?, host_path(host));
    }
    // Relative/non-special/file spellings are intentionally not parsed here.
    general_quote(n, n, add(n, 1)?, HostPath::Unclassified)
}

fn general_quote(n: u64, host_len: u64, ascii_labels: u64, path: HostPath) -> Result<u64> {
    if n == 0 {
        return Ok(0);
    }
    // Mapping can produce an ACE label which is decoded and normalized again.
    // The outer iterator may stay live during the inner one. Plain ASCII without
    // percent/ignored controls cannot hide mapped Unicode or an ACE prefix.
    let (normalized, outer, decoded_label, host_bytes, labels) = match path {
        HostPath::Ascii => (host_len, 0, 0, host_len, ascii_labels),
        HostPath::AsciiAce | HostPath::Unclassified => {
            let mapped = if matches!(path, HostPath::AsciiAce) {
                host_len
            } else {
                mul(host_len, MAX_DECOMPOSED_SCALARS)?
            };
            let normalized = mul(mapped, MAX_DECOMPOSED_SCALARS)?;
            let labels = add(normalized, 1)?;
            // Each label adds xn--4, optional basic separator1 and domain dot1.
            let host_bytes = add(mul(normalized, MAX_PUNYCODE_DIGITS)?, mul(labels, 6)?)?;
            let outer = if matches!(path, HostPath::AsciiAce) {
                0
            } else {
                mapped
            };
            (
                normalized,
                outer,
                mapped.min(PUNYCODE_DECODE_INPUT),
                host_bytes,
                labels,
            )
        }
    };
    // Paths/userinfo/query/fragments percent-expand each original byte to3;
    // scheme/authority/file syntax adds at most8. Host output is additional.
    let serialized = add(add(mul(n, 3)?, host_bytes)?, 8)?;
    let checked_label = mul(decoded_label, MAX_DECOMPOSED_SCALARS)?;

    let mut total = growing(serialized, 1, 0)?;
    total = add(total, growing(host_len, 1, 0)?)?; // filtered host String
    total = add(total, growing(host_len, 1, 0)?)?; // percent-decoded Vec<u8>
    total = add(total, growing(host_bytes, 1, 0)?)?; // ToASCII/opaque output
    total = add(total, backing(host_bytes)?)?; // owned Host conversion
    total = add(total, growing(normalized, size_of::<char>() as u64, 253)?)?;
    // Private AlreadyAsciiLabel holds a discriminant and borrowed slice;
    // four pointer words cover layout/alignment on qualified32/64-bit targets.
    total = add(
        total,
        growing(labels, mul(4, size_of::<usize>() as u64)?, 8)?,
    )?;
    total = add(total, growing(decoded_label, size_of::<char>() as u64, 59)?)?;
    total = add(
        total,
        growing(decoded_label, size_of::<(usize, char)>() as u64, 59)?,
    )?;
    total = add(
        total,
        sort_scratch(decoded_label, size_of::<(usize, char)>() as u64)?,
    )?;
    // Both ICU CharacterAndClass(u32) runs and their stable-sort scratch may
    // overlap when a Unicode-mapped ACE label starts its inner validation.
    total = add(total, growing(outer, size_of::<u32>() as u64, 17)?)?;
    total = add(total, sort_scratch(outer, size_of::<u32>() as u64)?)?;
    total = add(total, growing(checked_label, size_of::<u32>() as u64, 17)?)?;
    total = add(total, sort_scratch(checked_label, size_of::<u32>() as u64)?)?;
    // IPv4-looking hosts collect all dot parts before rejecting>4; numbers<=4.
    // Punycode encoding does not add dots inside a label.
    total = add(total, growing(labels, size_of::<&str>() as u64, 0)?)?;
    add(total, growing(4, size_of::<u32>() as u64, 0)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_quote_checks_every_size_before_wrapping() {
        assert_eq!(quote(""), Ok(0));
        assert_eq!(
            general_quote(u64::MAX, u64::MAX, u64::MAX, HostPath::Unclassified)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            mul(u64::MAX, 18).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(add(u64::MAX, 1).unwrap_err().code, ErrorCode::QuotaExceeded);
        assert_eq!(
            backing(u64::MAX).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
        assert!(
            general_quote(1024, 1024, 1025, HostPath::Unclassified).unwrap()
                > general_quote(512, 512, 513, HostPath::Unclassified).unwrap()
        );
    }
    #[test]
    fn endpoint_host_census_preserves_special_parser_delimiters() {
        for (input, expected) in [
            (
                "HTTPS:\\\\user:pass@node.invalid:443/path?query#fragment",
                "node.invalid",
            ),
            (
                "https:\t/\n/first@second@x\tn--bcher-kva.invalid:443/",
                "x\tn--bcher-kva.invalid",
            ),
            ("https://[::1]:8443/", "[::1]"),
            ("https://%40node.invalid/?q=a", "%40node.invalid"),
            ("https://node.invalid\\next", "node.invalid"),
        ] {
            assert_eq!(special_host(input), Some(expected), "{input:?}");
        }
        assert_eq!(special_host("file:///node.invalid/path"), None);
        assert_eq!(special_host("\nhttps://node.invalid/"), None);
        for host in [
            "%65xample.invalid",
            "xn--bcher-kva.invalid",
            "ab--node.invalid",
            "127.0.0.1",
            "NODE.invalid",
            "例え.invalid",
            "a..invalid",
            "x\tn--bcher-kva.invalid",
        ] {
            assert!(!ascii_passthrough_host(host), "{host}");
        }
        assert!(ascii_passthrough_host("node-1.example.invalid"));
        assert!(quote("https://node-1.example.invalid:8443/").unwrap() < 1024);
        assert!(matches!(
            host_path("xn--bcher-kva.invalid"),
            HostPath::AsciiAce
        ));
        assert!(matches!(
            host_path("x\tn--bcher-kva.invalid"),
            HostPath::Unclassified
        ));
        assert!(matches!(
            host_path("%78n--bcher-kva.invalid"),
            HostPath::Unclassified
        ));
    }
}
