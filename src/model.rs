#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BwItem {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub folder: Option<String>,
    pub item_type: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BwItemDetail {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Vec<String>,
    pub totp: Option<String>,
    pub notes: Option<String>,
    pub custom_fields: Vec<CustomField>,
    pub folder: Option<String>,
    pub item_type: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncStatus {
    pub server_ciphers: usize,
    pub decrypted_items: usize,
    pub skipped_items: usize,
    pub first_error: Option<String>,
}
