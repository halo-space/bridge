//! 用户登录因子。

pub mod basic;
#[cfg(feature = "enterprise")]
pub mod enterprise;
pub mod oidc;
pub mod passkey;
#[cfg(feature = "social")]
pub mod social;
