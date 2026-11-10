/// 图形验证码答案校验。
pub struct Image;

impl Image {
    /// 校验字符，忽略大小写和首尾空格。
    pub fn verify(expected: &str, input: &str) -> bool {
        expected.trim().eq_ignore_ascii_case(input.trim())
    }
}
