use crate::error::{Error, Result};
use crate::types::Identity;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, ldap_escape};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub server_url: String,
    pub base_dn: String,
    pub bind_dn: String,
    #[serde(default, skip_serializing)]
    pub bind_password: Option<String>,
    pub user_search_filter: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_timeout() -> u64 {
    8
}

pub struct LdapAuth;

impl LdapAuth {
    pub fn identity(username: &str) -> Identity {
        Identity::new("ldap", username)
    }

    pub async fn authenticate(
        config: &LdapConfig,
        username: &str,
        password: &str,
    ) -> Result<Identity> {
        if username.trim().is_empty() || password.is_empty() {
            return Err(Error::InvalidCredentials);
        }
        let filter = config
            .user_search_filter
            .replace("{username}", ldap_escape(username).as_ref());
        if filter == config.user_search_filter {
            return Err(Error::LdapError(
                "user_search_filter must contain {username}".into(),
            ));
        }

        let timeout = Duration::from_secs(config.timeout.max(1));
        let settings = LdapConnSettings::new().set_conn_timeout(timeout);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &config.server_url)
            .await
            .map_err(|e| Error::LdapError(format!("connect failed: {e}")))?;
        ldap3::drive!(conn);
        ldap.with_timeout(timeout);

        if !config.bind_dn.is_empty() {
            let bind_password = config.bind_password.as_deref().unwrap_or_default();
            ldap.simple_bind(&config.bind_dn, bind_password)
                .await
                .map_err(|e| Error::LdapError(format!("service bind failed: {e}")))?
                .success()
                .map_err(|e| Error::LdapError(format!("service bind rejected: {e}")))?;
        } else {
            ldap.simple_bind("", "")
                .await
                .map_err(|e| Error::LdapError(format!("anonymous bind failed: {e}")))?
                .success()
                .map_err(|e| Error::LdapError(format!("anonymous bind rejected: {e}")))?;
        }

        let (entries, _) = ldap
            .search(
                &config.base_dn,
                Scope::Subtree,
                &filter,
                vec!["uid", "mail", "telephoneNumber", "displayName", "cn"],
            )
            .await
            .map_err(|e| Error::LdapError(format!("user search failed: {e}")))?
            .success()
            .map_err(|e| Error::LdapError(format!("user search rejected: {e}")))?;
        if entries.len() != 1 {
            return Err(Error::InvalidCredentials);
        }
        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
        let user_dn = entry.dn.clone();
        ldap.simple_bind(&user_dn, password)
            .await
            .map_err(|e| Error::LdapError(format!("user bind failed: {e}")))?
            .success()
            .map_err(|_| Error::InvalidCredentials)?;
        let _ = ldap.unbind().await;

        let subject = entry
            .attrs
            .get("uid")
            .and_then(|values| values.first())
            .cloned()
            .unwrap_or(user_dn);
        let mut identity = Identity::new("ldap", subject);
        if let Some(email) = entry.attrs.get("mail").and_then(|values| values.first()) {
            identity = identity.email(email);
        }
        if let Some(phone) = entry
            .attrs
            .get("telephoneNumber")
            .and_then(|values| values.first())
        {
            identity = identity.phone(phone);
        }
        if let Some(name) = entry
            .attrs
            .get("displayName")
            .or_else(|| entry.attrs.get("cn"))
            .and_then(|values| values.first())
        {
            identity = identity.name(name);
        }
        Ok(identity)
    }
}
