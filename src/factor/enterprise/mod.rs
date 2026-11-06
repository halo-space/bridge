pub mod device;
pub mod dingtalk;
pub mod ldap;
pub mod oidc;
pub mod saml;
pub mod wecom;

pub use dingtalk::{DingtalkConfig, DingtalkProvider};
pub use ldap::{LdapAuth, LdapConfig};
pub use oidc::{OidcConfig, OidcProfile, OidcProvider};
pub use saml::{SamlAssertion, SamlAuth, SamlConfig};
pub use wecom::{WecomConfig, WecomProvider};
