#[path = "../src/packed.rs"]
mod packed;

#[test]
fn mixed_size_rows_bound_both_complete_bytes_and_retained_vec_capacity() {
    let mut page = Vec::new();
    let large = vec![7; 20 << 20];
    for (key, value) in [
        (b"a", &large[..]),
        (b"b", &large[..]),
        (b"c", &large[..1 << 20]),
    ] {
        packed::append_row(&mut page, key, value).unwrap();
        assert!(page.capacity() <= packed::MAX_RANGE_BYTES);
    }
    assert_eq!(page.len(), (41 << 20) + 27);
    let remaining = packed::MAX_RANGE_BYTES - page.len() - 8;
    packed::append_row(&mut page, b"", &vec![1; remaining]).unwrap();
    assert_eq!(page.len(), packed::MAX_RANGE_BYTES);
    assert_eq!(page.capacity(), packed::MAX_RANGE_BYTES);
    assert!(packed::append_row(&mut page, b"", b"").is_err());
    assert_eq!(page.len(), packed::MAX_RANGE_BYTES);
}
