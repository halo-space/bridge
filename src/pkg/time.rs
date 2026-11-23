use jiff::Timestamp;

/// 当前 Unix 秒时间戳。
pub fn now() -> i64 {
    Timestamp::now().as_second()
}

/// 将 Unix 秒格式化为 UTC 日期文本。
pub fn date(timestamp: i64) -> Option<String> {
    Some(
        Timestamp::from_second(timestamp)
            .ok()?
            .strftime("%Y-%m-%d")
            .to_string(),
    )
}

/// 将当前时间格式化为 RFC 3339 UTC 文本。
pub fn text() -> String {
    Timestamp::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// 解析 RFC 3339 时间并返回 Unix 秒时间戳。
pub fn parse(value: &str) -> Option<i64> {
    value.parse::<Timestamp>().ok().map(Timestamp::as_second)
}
