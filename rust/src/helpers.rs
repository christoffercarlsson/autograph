pub fn get_uint32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub fn set_uint32(bytes: &mut [u8], offset: usize, number: u32) {
    bytes[offset..offset + 4].copy_from_slice(number.to_be_bytes().as_slice());
}
