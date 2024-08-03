pub fn utf8_len(byte: u8) -> u8 {
    if byte & 0b1000_0000 == 0 {
        // 0xxxxxxx (ASCII)
        1
    } else if byte & 0b1110_0000 == 0b1100_0000 {
        // 110xxxxx
        2
    } else if byte & 0b1111_0000 == 0b1110_0000 {
        // 1110xxxx
        3
    } else if byte & 0b1111_1000 == 0b1111_0000 {
        // 11110xxx
        4
    } else {
        // 2 msb == 10 means continuation bit
        0
    }
}
