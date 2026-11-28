//! Buffer size for the variable-length NT structures that end in a file name
//! (`FILE_LINK_INFORMATION`). Kept free of FFI so the arithmetic is tested on
//! every host.

/// Bytes to pass to `NtSetInformationFile`: the name starts at `name_offset`,
/// but the kernel also requires at least `struct_size` bytes. The structure
/// declares `FileName` as `[u16; 1]`, so for a one-character name
/// `name_offset + name_bytes` (22 on 64-bit) is smaller than the structure
/// (24) and NT answers `STATUS_INFO_LENGTH_MISMATCH`. `None` on overflow.
pub(crate) fn name_info_len(
    struct_size: usize,
    name_offset: usize,
    name_bytes: usize,
) -> Option<usize> {
    name_offset
        .checked_add(name_bytes)
        .map(|end| end.max(struct_size))
}

#[cfg(test)]
mod tests {
    use super::name_info_len;

    // FILE_LINK_INFORMATION on 64-bit: 24 bytes, FileName at offset 20.
    const STRUCT: usize = 24;
    const OFFSET: usize = 20;

    #[test]
    fn a_one_character_name_is_padded_to_the_structure_size() {
        assert_eq!(name_info_len(STRUCT, OFFSET, 2), Some(24));
    }

    #[test]
    fn a_name_that_reaches_past_the_structure_adds_its_bytes() {
        assert_eq!(name_info_len(STRUCT, OFFSET, 6), Some(26));
        assert_eq!(name_info_len(STRUCT, OFFSET, 255 * 2), Some(530));
    }

    #[test]
    fn the_length_is_never_below_the_structure_or_the_name_end() {
        for bytes in (0..=1000).step_by(2) {
            let len = name_info_len(STRUCT, OFFSET, bytes).unwrap();
            assert!(len >= STRUCT && len >= OFFSET + bytes);
        }
    }

    #[test]
    fn overflow_is_reported() {
        assert_eq!(name_info_len(STRUCT, OFFSET, usize::MAX), None);
    }
}
