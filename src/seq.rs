//! TCP 序号的 32 位环绕比较（RFC 1982 风格）。
//! 所有比较仅在序号差小于 2^31 时有效，这是 TCP 序号空间的标准假设。

/// a < b（环绕意义下）
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// a <= b（环绕意义下）
pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// a > b（环绕意义下）
pub fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}

/// a - b 的有符号差（环绕意义下，|差| < 2^31 时有效）
pub fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraparound_compare() {
        assert!(seq_lt(0xFFFF_FFF0, 10));
        assert!(seq_gt(10, 0xFFFF_FFF0));
        assert!(seq_le(0xFFFF_FFF0, 0xFFFF_FFF0));
        assert_eq!(seq_diff(5, 0xFFFF_FFF0), 21);
        assert_eq!(seq_diff(0xFFFF_FFF0, 5), -21);
        assert!(seq_lt(1_000_000, 2_000_000));
        assert!(seq_gt(2_000_000, 1_000_000));
    }
}
