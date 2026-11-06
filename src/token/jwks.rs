use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::RsaPublicKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};

/// OIDC 标准 JWKS 密钥项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub alg: String,
    pub n: Option<String>,
    pub e: Option<String>,
}

/// OIDC 标准 /.well-known/jwks.json 返回集合
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

impl JwksResponse {
    pub fn new(keys: Vec<JwkKey>) -> Self {
        Self { keys }
    }

    /// 从 RSA 公钥组件构造标准 RS256 JWKS 响应
    pub fn from_rsa_components(n: &[u8], e: &[u8], kid: impl Into<String>) -> Self {
        let n_b64 = BASE64_URL_SAFE_NO_PAD.encode(n);
        let e_b64 = BASE64_URL_SAFE_NO_PAD.encode(e);

        Self {
            keys: vec![JwkKey {
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
                kid: kid.into(),
                alg: "RS256".to_string(),
                n: Some(n_b64),
                e: Some(e_b64),
            }],
        }
    }

    /// 从标准 `RsaPublicKey` 对象直接生成 JWKS
    pub fn from_rsa_public_key(public_key: &RsaPublicKey, kid: impl Into<String>) -> Self {
        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();
        Self::from_rsa_components(&n_bytes, &e_bytes, kid)
    }
}
