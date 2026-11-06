pub mod flow;
pub mod nonce;
pub mod pkce;
pub mod server;
pub mod state;

pub use nonce::Nonce;
pub use pkce::Pkce;
pub use state::State;

pub(crate) fn same(left: &str, right: &str) -> bool {
    let mut diff = left.len() ^ right.len();
    for (a, b) in left.bytes().zip(right.bytes()) {
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

pub use flow::{AuthorizeRequest, OidcFlow, TokenRequest};
pub use server::{
    IntrospectRequest, IntrospectResponse, OidcDiscovery, RevokeRequest, TokenResponse,
    UserInfoResponse,
};
