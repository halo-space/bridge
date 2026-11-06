use serde::{Deserialize, Serialize};
use crate::error::{IdpError, Result};

/// 外部组织部门模型 (统一抽象)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalDepartment {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub order: u32,
}

/// 外部企业员工模型 (统一抽象)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalUser {
    pub id: String,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub department_ids: Vec<String>,
    pub position: Option<String>,
    /// 1=正常, 2=已禁用, 4=已离职
    pub status: i16,
}

/// 同步执行统计摘要
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncStats {
    pub total_depts_fetched: usize,
    pub total_users_fetched: usize,
    pub errors: Vec<String>,
}

/// 企业微信通讯录同步客户端
pub struct WeComSyncClient {
    http: reqwest::Client,
}

impl Default for WeComSyncClient {
    fn default() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }
}

impl WeComSyncClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取 WeCom access_token
    async fn get_access_token(&self, corp_id: &str, corp_secret: &str) -> Result<String> {
        let url = format!(
            "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={}&corpsecret={}",
            corp_id, corp_secret
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| IdpError::SyncError(format!("WeCom token request failed: {e}")))?;

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IdpError::SyncError(format!("Invalid WeCom token response: {e}")))?;

        if val.get("errcode").and_then(|v| v.as_i64()) == Some(0) {
            val.get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| IdpError::SyncError("Missing access_token in response".to_string()))
        } else {
            let msg = val.get("errmsg").and_then(|v| v.as_str()).unwrap_or("unknown");
            Err(IdpError::SyncError(format!("WeCom auth error: {msg}")))
        }
    }

    /// 拉取全量企业微信部门列表
    pub async fn fetch_departments(
        &self,
        corp_id: &str,
        corp_secret: &str,
    ) -> Result<Vec<ExternalDepartment>> {
        let token = self.get_access_token(corp_id, corp_secret).await?;
        let url = format!(
            "https://qyapi.weixin.qq.com/cgi-bin/department/list?access_token={}",
            token
        );

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| IdpError::SyncError(format!("WeCom department fetch error: {e}")))?;

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IdpError::SyncError(format!("Invalid JSON from WeCom: {e}")))?;

        let mut list = Vec::new();
        if let Some(arr) = val.get("department").and_then(|v| v.as_array()) {
            for item in arr {
                let id = item.get("id").and_then(|v| v.as_i64()).unwrap_or(0).to_string();
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let parent_id = item
                    .get("parentid")
                    .and_then(|v| v.as_i64())
                    .filter(|&p| p > 0)
                    .map(|p| p.to_string());
                let order = item.get("order").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

                list.push(ExternalDepartment {
                    id,
                    name,
                    parent_id,
                    order,
                });
            }
        }
        Ok(list)
    }

    /// 拉取部门下的全量成员
    pub async fn fetch_users(
        &self,
        corp_id: &str,
        corp_secret: &str,
        dept_id: &str,
    ) -> Result<Vec<ExternalUser>> {
        let token = self.get_access_token(corp_id, corp_secret).await?;
        let url = format!(
            "https://qyapi.weixin.qq.com/cgi-bin/user/list?access_token={}&department_id={}&fetch_child=1",
            token, dept_id
        );

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| IdpError::SyncError(format!("WeCom users fetch error: {e}")))?;

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IdpError::SyncError(format!("Invalid JSON from WeCom: {e}")))?;

        let mut list = Vec::new();
        if let Some(arr) = val.get("userlist").and_then(|v| v.as_array()) {
            for item in arr {
                let id = item.get("userid").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let email = item.get("email").and_then(|v| v.as_str()).map(|s| s.to_string());
                let phone = item.get("mobile").and_then(|v| v.as_str()).map(|s| s.to_string());
                let position = item.get("position").and_then(|v| v.as_str()).map(|s| s.to_string());
                let status = item.get("status").and_then(|v| v.as_i64()).unwrap_or(1) as i16;

                let dept_ids = item
                    .get("department")
                    .and_then(|v| v.as_array())
                    .map(|d_arr| {
                        d_arr
                            .iter()
                            .filter_map(|d| d.as_i64().map(|n| n.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                list.push(ExternalUser {
                    id: id.clone(),
                    username: id,
                    name,
                    email,
                    phone,
                    department_ids: dept_ids,
                    position,
                    status,
                });
            }
        }
        Ok(list)
    }
}

/// 飞书通讯录同步客户端
pub struct FeishuSyncClient {
    http: reqwest::Client,
}

impl Default for FeishuSyncClient {
    fn default() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }
}

impl FeishuSyncClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取飞书 tenant_access_token
    async fn get_tenant_access_token(&self, app_id: &str, app_secret: &str) -> Result<String> {
        let url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal";
        let body = serde_json::json!({
            "app_id": app_id,
            "app_secret": app_secret
        });

        let resp = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| IdpError::SyncError(format!("Feishu token request failed: {e}")))?;

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IdpError::SyncError(format!("Invalid Feishu token response: {e}")))?;

        if val.get("code").and_then(|v| v.as_i64()) == Some(0) {
            val.get("tenant_access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| IdpError::SyncError("Missing tenant_access_token in response".to_string()))
        } else {
            let msg = val.get("msg").and_then(|v| v.as_str()).unwrap_or("unknown");
            Err(IdpError::SyncError(format!("Feishu auth error: {msg}")))
        }
    }

    /// 拉取飞书全量部门列表（自动处理游标分页）
    pub async fn fetch_departments(
        &self,
        app_id: &str,
        app_secret: &str,
    ) -> Result<Vec<ExternalDepartment>> {
        let token = self.get_tenant_access_token(app_id, app_secret).await?;
        let mut list = Vec::new();
        let mut page_token = String::new();

        loop {
            let mut url = format!(
                "https://open.feishu.cn/open-apis/contact/v3/departments?department_id_type=open_department_id&page_size=50"
            );
            if !page_token.is_empty() {
                url.push_str(&format!("&page_token={page_token}"));
            }

            let resp = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| IdpError::SyncError(format!("Feishu department fetch error: {e}")))?;

            let val: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| IdpError::SyncError(format!("Invalid JSON from Feishu: {e}")))?;

            if let Some(items) = val.get("data").and_then(|d| d.get("items")).and_then(|v| v.as_array()) {
                for item in items {
                    let id = item.get("open_department_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let parent_id = item
                        .get("parent_department_id")
                        .and_then(|v| v.as_str())
                        .filter(|&p| p != "0" && !p.is_empty())
                        .map(|p| p.to_string());
                    let order = item.get("order").and_then(|v| v.as_i64()).unwrap_or(0) as u32;

                    list.push(ExternalDepartment {
                        id,
                        name,
                        parent_id,
                        order,
                    });
                }
            }

            let has_more = val.get("data").and_then(|d| d.get("has_more")).and_then(|v| v.as_bool()).unwrap_or(false);
            if !has_more {
                break;
            }
            if let Some(next_token) = val.get("data").and_then(|d| d.get("page_token")).and_then(|v| v.as_str()) {
                if next_token.is_empty() || next_token == page_token {
                    break;
                }
                page_token = next_token.to_string();
            } else {
                break;
            }
        }

        Ok(list)
    }

    /// 拉取飞书全量员工列表（自动处理游标分页）
    pub async fn fetch_users(
        &self,
        app_id: &str,
        app_secret: &str,
    ) -> Result<Vec<ExternalUser>> {
        let token = self.get_tenant_access_token(app_id, app_secret).await?;
        let mut list = Vec::new();
        let mut page_token = String::new();

        loop {
            let mut url = format!(
                "https://open.feishu.cn/open-apis/contact/v3/users?user_id_type=open_id&page_size=50"
            );
            if !page_token.is_empty() {
                url.push_str(&format!("&page_token={page_token}"));
            }

            let resp = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| IdpError::SyncError(format!("Feishu users fetch error: {e}")))?;

            let val: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| IdpError::SyncError(format!("Invalid JSON from Feishu: {e}")))?;

            if let Some(items) = val.get("data").and_then(|d| d.get("items")).and_then(|v| v.as_array()) {
                for item in items {
                    let id = item.get("open_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let email = item.get("email").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let phone = item.get("mobile").and_then(|v| v.as_str()).map(|s| s.to_string());

                    let dept_ids = item
                        .get("department_ids")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter().filter_map(|d| d.as_str().map(|s| s.to_string())).collect()
                        })
                        .unwrap_or_default();

                    list.push(ExternalUser {
                        id: id.clone(),
                        username: id,
                        name,
                        email,
                        phone,
                        department_ids: dept_ids,
                        position: None,
                        status: 1,
                    });
                }
            }

            let has_more = val.get("data").and_then(|d| d.get("has_more")).and_then(|v| v.as_bool()).unwrap_or(false);
            if !has_more {
                break;
            }
            if let Some(next_token) = val.get("data").and_then(|d| d.get("page_token")).and_then(|v| v.as_str()) {
                if next_token.is_empty() || next_token == page_token {
                    break;
                }
                page_token = next_token.to_string();
            } else {
                break;
            }
        }

        Ok(list)
    }
}

/// SCIM 2.0 (RFC 7643) 标准数据模型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    pub user_name: String,
    pub name: ScimName,
    pub emails: Vec<ScimEmail>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    pub formatted: String,
    pub family_name: Option<String>,
    pub given_name: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    pub primary: bool,
    #[serde(rename = "type")]
    pub email_type: String,
}

impl ExternalUser {
    /// 转换为标准 SCIM 2.0 用户格式
    pub fn to_scim(&self) -> ScimUser {
        ScimUser {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
            id: self.id.clone(),
            user_name: self.username.clone(),
            name: ScimName {
                formatted: self.name.clone(),
                family_name: None,
                given_name: Some(self.name.clone()),
            },
            emails: self
                .email
                .as_ref()
                .map(|e| {
                    vec![ScimEmail {
                        value: e.clone(),
                        primary: true,
                        email_type: "work".to_string(),
                    }]
                })
                .unwrap_or_default(),
            active: self.status == 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_user_to_scim() {
        let user = ExternalUser {
            id: "user_888".to_string(),
            username: "zhangsan".to_string(),
            name: "张三".to_string(),
            email: Some("zhangsan@company.com".to_string()),
            phone: Some("13800000000".to_string()),
            department_ids: vec!["dept_1".to_string()],
            position: Some("架构师".to_string()),
            status: 1,
        };

        let scim = user.to_scim();
        assert_eq!(scim.id, "user_888");
        assert_eq!(scim.user_name, "zhangsan");
        assert!(scim.active);
        assert_eq!(scim.emails.len(), 1);
        assert_eq!(scim.emails[0].value, "zhangsan@company.com");
    }
}
