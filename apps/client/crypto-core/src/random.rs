//! 系统安全随机源封装。

/// 用操作系统的安全随机源填充缓冲区。
pub fn fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("操作系统安全随机源不可用");
}

/// 生成 N 字节随机数组。
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill(&mut b);
    b
}
