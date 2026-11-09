use super::{BoxFuture, Sender};
use crate::error::Error;

pub(crate) struct Unknown {
    provider: String,
}

impl Unknown {
    pub(crate) fn new(provider: String) -> Self {
        Self { provider }
    }
}

impl Sender for Unknown {
    fn send<'a>(&'a self, _phone: &'a str, _code: &'a str, _ttl_secs: u64) -> BoxFuture<'a> {
        let provider = self.provider.clone();
        Box::pin(async move {
            Err(Error::SmsFailed(format!(
                "Unsupported SMS provider: {provider}"
            )))
        })
    }
}
