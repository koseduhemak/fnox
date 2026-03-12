use crate::config::SecretFilter;
use crate::env;
use crate::error::{FnoxError, Result};
use crate::providers::ProviderCapability;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;

const URL: &str = "https://fnox.jdx.dev/providers/enpass";
const PROVIDER: &str = "Enpass";

const SALT_LENGTH: usize = 16;
// First 64 hex chars (32 bytes) of the derived key
const MASTER_KEY_HEX_LENGTH: usize = 64;

pub fn env_dependencies() -> &'static [&'static str] {
    &["FNOX_ENPASS_PASSWORD", "ENPASS_PASSWORD"]
}

#[derive(Debug, serde::Deserialize)]
struct VaultInfo {
    encryption_algo: String,
    #[serde(rename = "have_keyfile")]
    has_keyfile: u8,
    kdf_algo: String,
    kdf_iter: u32,
    #[allow(dead_code)]
    vault_name: Option<String>,
}

struct EnpassItem {
    uuid: String,
    title: String,
    label: String,
    value: String,
    item_key: Vec<u8>,
    sensitive: bool,
    trashed: i64,
    deleted: i64,
    category: String,
    favorite: bool,
    archived: bool,
}

pub struct EnpassProvider {
    vault_path: PathBuf,
    keyfile_path: Option<PathBuf>,
}

impl EnpassProvider {
    pub fn new(vault_path: String, keyfile: Option<String>) -> Result<Self> {
        Ok(Self {
            vault_path: PathBuf::from(shellexpand::tilde(&vault_path).to_string()),
            keyfile_path: keyfile.map(|k| PathBuf::from(shellexpand::tilde(&k).to_string())),
        })
    }

    fn get_password() -> Result<String> {
        enpass_password().ok_or_else(|| FnoxError::ProviderAuthFailed {
            provider: PROVIDER.to_string(),
            details: "Vault password not set".to_string(),
            hint: "Set FNOX_ENPASS_PASSWORD or ENPASS_PASSWORD environment variable".to_string(),
            url: URL.to_string(),
        })
    }

    fn load_vault_info(&self) -> Result<VaultInfo> {
        let info_path = self.vault_path.join("vault.json");
        let content =
            std::fs::read_to_string(&info_path).map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Failed to read vault info '{}': {}", info_path.display(), e),
                hint: "Check that the vault directory contains vault.json".to_string(),
                url: URL.to_string(),
            })?;

        let info: VaultInfo =
            serde_json::from_str(&content).map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Failed to parse vault.json: {}", e),
                hint: "Check that vault.json is valid".to_string(),
                url: URL.to_string(),
            })?;

        if info.kdf_algo != "pbkdf2" {
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Unsupported KDF algorithm: {}", info.kdf_algo),
                hint: "Only pbkdf2 is supported".to_string(),
                url: URL.to_string(),
            });
        }

        if info.encryption_algo != "aes-256-cbc" {
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Unsupported encryption algorithm: {}", info.encryption_algo),
                hint: "Only aes-256-cbc is supported".to_string(),
                url: URL.to_string(),
            });
        }

        Ok(info)
    }

    fn extract_salt(&self) -> Result<Vec<u8>> {
        let db_path = self.vault_path.join("vault.enpassdb");
        let data = std::fs::read(&db_path).map_err(|e| FnoxError::ProviderApiError {
            provider: PROVIDER.to_string(),
            details: format!(
                "Failed to read vault database '{}': {}",
                db_path.display(),
                e
            ),
            hint: "Check that the vault directory contains vault.enpassdb".to_string(),
            url: URL.to_string(),
        })?;

        if data.len() < SALT_LENGTH {
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: "Vault database file is too small to contain a salt".to_string(),
                hint: "The vault.enpassdb file may be corrupted".to_string(),
                url: URL.to_string(),
            });
        }

        Ok(data[..SALT_LENGTH].to_vec())
    }

    fn generate_master_password(&self, password: &[u8], vault_info: &VaultInfo) -> Result<Vec<u8>> {
        if vault_info.has_keyfile == 1 {
            let keyfile_path =
                self.keyfile_path
                    .as_ref()
                    .ok_or_else(|| FnoxError::ProviderApiError {
                        provider: PROVIDER.to_string(),
                        details: "Vault requires a keyfile but none was configured".to_string(),
                        hint: "Set keyfile in provider config".to_string(),
                        url: URL.to_string(),
                    })?;
            let keyfile_bytes = load_keyfile(keyfile_path)?;
            let mut combined = password.to_vec();
            combined.extend_from_slice(&keyfile_bytes);
            Ok(combined)
        } else if self.keyfile_path.is_some() {
            Err(FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: "Keyfile configured but vault does not use a keyfile".to_string(),
                hint: "Remove keyfile from provider config".to_string(),
                url: URL.to_string(),
            })
        } else {
            Ok(password.to_vec())
        }
    }

    fn derive_key(&self, master_password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        // PBKDF2-HMAC-SHA512, output 64 bytes (SHA-512 size)
        let mut key = vec![0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(master_password, salt, iterations, &mut key);
        key
    }

    fn open_database(&self) -> Result<rusqlite::Connection> {
        let vault_info = self.load_vault_info()?;
        let password = Self::get_password()?;
        let master_password = self.generate_master_password(password.as_bytes(), &vault_info)?;
        let salt = self.extract_salt()?;
        let db_key = self.derive_key(&master_password, &salt, vault_info.kdf_iter);

        // The raw key for SQLCipher is the first 64 hex chars (32 bytes) of the derived key
        let hex_key = hex::encode(&db_key);
        let hex_key = &hex_key[..MASTER_KEY_HEX_LENGTH];

        let db_path = self.vault_path.join("vault.enpassdb");

        // Try SQLCipher v4 first, then fall back to v3
        for cipher_version in [4, 3] {
            match self.try_open_db(&db_path, hex_key, cipher_version) {
                Ok(conn) => {
                    tracing::debug!(cipher_version, "Successfully opened Enpass database");
                    return Ok(conn);
                }
                Err(e) => {
                    tracing::debug!(
                        cipher_version,
                        error = %e,
                        "Failed to open database with cipher version"
                    );
                }
            }
        }

        Err(FnoxError::ProviderAuthFailed {
            provider: PROVIDER.to_string(),
            details: "Could not open vault database: invalid password or unsupported version"
                .to_string(),
            hint: "Check that the password is correct".to_string(),
            url: URL.to_string(),
        })
    }

    fn try_open_db(
        &self,
        db_path: &std::path::Path,
        hex_key: &str,
        cipher_version: u8,
    ) -> std::result::Result<rusqlite::Connection, rusqlite::Error> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.pragma_update(None, "key", format!("x'{hex_key}'"))?;
        conn.pragma_update(None, "cipher_compatibility", cipher_version)?;

        // Verify the database is actually readable
        let _count: i32 =
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;

        Ok(conn)
    }

    fn query_items(&self, conn: &rusqlite::Connection) -> Result<Vec<EnpassItem>> {
        let mut stmt = conn
            .prepare(
                "SELECT i.uuid, i.title, f.label, f.value, i.key, f.sensitive,
                        i.trashed, i.deleted, COALESCE(i.category, ''),
                        COALESCE(i.favorite, 0), COALESCE(i.archived, 0)
                 FROM item i
                 INNER JOIN itemfield f ON i.uuid = f.item_uuid
                 WHERE i.deleted = 0 AND f.deleted = 0",
            )
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Failed to query vault: {}", e),
                hint: "The vault database may be corrupted".to_string(),
                url: URL.to_string(),
            })?;

        let items = stmt
            .query_map([], |row| {
                Ok(EnpassItem {
                    uuid: row.get(0)?,
                    title: row.get(1)?,
                    label: row.get(2)?,
                    value: row.get(3)?,
                    item_key: row.get(4)?,
                    sensitive: row.get::<_, i64>(5)? != 0,
                    trashed: row.get(6)?,
                    deleted: row.get(7)?,
                    category: row.get(8)?,
                    favorite: row.get::<_, i64>(9)? != 0,
                    archived: row.get::<_, i64>(10)? != 0,
                })
            })
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Failed to query vault items: {}", e),
                hint: "The vault database may be corrupted".to_string(),
                url: URL.to_string(),
            })?;

        let mut result = Vec::new();
        for item in items {
            result.push(item.map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Failed to read vault item: {}", e),
                hint: "The vault database may be corrupted".to_string(),
                url: URL.to_string(),
            })?);
        }

        Ok(result)
    }

    fn decrypt_field(item: &EnpassItem) -> Result<String> {
        if item.value.is_empty() {
            return Ok(String::new());
        }

        // Non-sensitive (non-password type) fields are stored in plaintext
        if !item.sensitive {
            return Ok(item.value.clone());
        }

        // item.key = 32 bytes AES key + 12 bytes GCM nonce
        if item.item_key.len() < 44 {
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!(
                    "Invalid item key length ({} bytes, expected 44) for '{}'",
                    item.item_key.len(),
                    item.title
                ),
                hint: "The item may have been deleted or is corrupted".to_string(),
                url: URL.to_string(),
            });
        }

        let key = &item.item_key[..32];
        let nonce_bytes = &item.item_key[32..44];

        // Value is hex-encoded ciphertext + GCM tag
        let ciphertext_and_tag =
            hex::decode(&item.value).map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!(
                    "Failed to decode encrypted value for '{}': {}",
                    item.title, e
                ),
                hint: "The encrypted value is corrupted".to_string(),
                url: URL.to_string(),
            })?;

        // AAD = UUID without dashes, hex-decoded
        let uuid_no_dashes = item.uuid.replace('-', "");
        let aad = hex::decode(&uuid_no_dashes).map_err(|e| FnoxError::ProviderApiError {
            provider: PROVIDER.to_string(),
            details: format!("Failed to decode UUID for '{}': {}", item.title, e),
            hint: "The item UUID is malformed".to_string(),
            url: URL.to_string(),
        })?;

        // AES-256-GCM decryption
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| FnoxError::ProviderApiError {
            provider: PROVIDER.to_string(),
            details: format!("Failed to initialize cipher for '{}': {}", item.title, e),
            hint: "The item key may be corrupted".to_string(),
            url: URL.to_string(),
        })?;

        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: &ciphertext_and_tag,
            aad: &aad,
        };

        let plaintext =
            cipher
                .decrypt(nonce, payload)
                .map_err(|e| FnoxError::ProviderApiError {
                    provider: PROVIDER.to_string(),
                    details: format!("Failed to decrypt field for '{}': {}", item.title, e),
                    hint: "The item data may be corrupted".to_string(),
                    url: URL.to_string(),
                })?;

        String::from_utf8(plaintext).map_err(|e| FnoxError::ProviderApiError {
            provider: PROVIDER.to_string(),
            details: format!(
                "Decrypted value is not valid UTF-8 for '{}': {}",
                item.title, e
            ),
            hint: "The decrypted value contains non-UTF-8 bytes".to_string(),
            url: URL.to_string(),
        })
    }

    /// Parse a reference into (item_title, field_label).
    /// Formats:
    /// - "my-item" -> ("my-item", None) — returns the password/sensitive field
    /// - "my-item/password" -> ("my-item", Some("password"))
    /// - "my-item/username" -> ("my-item", Some("username"))
    fn parse_reference(value: &str) -> (&str, Option<&str>) {
        match value.rsplit_once('/') {
            Some((title, field)) => (title, Some(field)),
            None => (value, None),
        }
    }

    /// Query folder/tag assignments for items.
    /// Returns a map of item_uuid -> Vec<tag_name>.
    fn query_tags(&self, conn: &rusqlite::Connection) -> Result<HashMap<String, Vec<String>>> {
        let mut stmt = conn
            .prepare(
                "SELECT fi.item_uuid, f.title
                 FROM folder_items fi
                 INNER JOIN folder f ON fi.folder_uuid = f.uuid
                 WHERE COALESCE(fi.deleted, 0) = 0 AND COALESCE(f.deleted, 0) = 0",
            )
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Failed to query folder/tags: {}", e),
                hint: "The vault database may be corrupted".to_string(),
                url: URL.to_string(),
            })?;

        let mut tags: HashMap<String, Vec<String>> = HashMap::new();
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!("Failed to query folder/tag items: {}", e),
                hint: "The vault database may be corrupted".to_string(),
                url: URL.to_string(),
            })?;

        for (item_uuid, tag_name) in rows.flatten() {
            tags.entry(item_uuid).or_default().push(tag_name);
        }

        Ok(tags)
    }

    fn resolve_from_items_filtered(
        items: &[EnpassItem],
        value: &str,
        filter: Option<&SecretFilter>,
        tags: &HashMap<String, Vec<String>>,
    ) -> Result<String> {
        let (title, field_label) = Self::parse_reference(value);

        // Find matching items by title (not trashed or deleted)
        let matching: Vec<&EnpassItem> = items
            .iter()
            .filter(|i| i.title.eq_ignore_ascii_case(title) && i.trashed == 0 && i.deleted == 0)
            .collect();

        if matching.is_empty() {
            return Err(FnoxError::ProviderSecretNotFound {
                provider: PROVIDER.to_string(),
                secret: title.to_string(),
                hint: "Check that the item title exists in the vault".to_string(),
                url: URL.to_string(),
            });
        }

        // Get unique item UUIDs that match the title
        let mut unique_uuids: Vec<&str> = matching.iter().map(|i| i.uuid.as_str()).collect();
        unique_uuids.sort();
        unique_uuids.dedup();

        // Apply filter if present to narrow down which item UUIDs are valid
        let filtered_uuids = if let Some(filter) = filter {
            Self::apply_filter(&unique_uuids, filter, &matching, tags)?
        } else {
            unique_uuids.clone()
        };

        if filtered_uuids.is_empty() {
            let item_tags: Vec<String> = unique_uuids
                .iter()
                .map(|uuid| {
                    let item_tags = tags.get(*uuid).map(|t| t.join(", ")).unwrap_or_default();
                    let cat = matching
                        .iter()
                        .find(|i| i.uuid == *uuid)
                        .map(|i| i.category.as_str())
                        .unwrap_or("");
                    format!(
                        "  - uuid={}, category='{}', tags=[{}]",
                        uuid, cat, item_tags
                    )
                })
                .collect();
            return Err(FnoxError::ProviderSecretNotFound {
                provider: PROVIDER.to_string(),
                secret: value.to_string(),
                hint: format!(
                    "No items named '{}' matched the filter. Available items:\n{}",
                    title,
                    item_tags.join("\n")
                ),
                url: URL.to_string(),
            });
        }

        // Error on ambiguity: multiple items match after filtering
        if filtered_uuids.len() > 1 && filter.is_some() {
            let item_info: Vec<String> = filtered_uuids
                .iter()
                .map(|uuid| {
                    let item_tags = tags.get(*uuid).map(|t| t.join(", ")).unwrap_or_default();
                    let cat = matching
                        .iter()
                        .find(|i| i.uuid == *uuid)
                        .map(|i| i.category.as_str())
                        .unwrap_or("");
                    format!(
                        "  - uuid={}, category='{}', tags=[{}]",
                        uuid, cat, item_tags
                    )
                })
                .collect();
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER.to_string(),
                details: format!(
                    "Multiple items named '{}' found ({} matches)",
                    title,
                    filtered_uuids.len()
                ),
                hint: format!(
                    "Use 'filter' to disambiguate. Matching items:\n{}\nExample: filter = {{ tag = \"my-tag\" }} or filter = {{ Username = \"user@example.com\" }}",
                    item_info.join("\n")
                ),
                url: URL.to_string(),
            });
        }

        // Single item UUID matched — resolve field from that item
        let target_uuid = filtered_uuids[0];
        let item_fields: Vec<&EnpassItem> = matching
            .iter()
            .filter(|i| i.uuid == target_uuid)
            .copied()
            .collect();

        match field_label {
            Some(label) => {
                let item = item_fields
                    .iter()
                    .find(|i| i.label.eq_ignore_ascii_case(label))
                    .ok_or_else(|| FnoxError::ProviderSecretNotFound {
                        provider: PROVIDER.to_string(),
                        secret: value.to_string(),
                        hint: format!(
                            "Field '{}' not found in item '{}'. Available fields: {}",
                            label,
                            title,
                            item_fields
                                .iter()
                                .map(|i| i.label.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        url: URL.to_string(),
                    })?;
                Self::decrypt_field(item)
            }
            None => {
                let item = item_fields
                    .iter()
                    .find(|i| i.sensitive)
                    .or_else(|| item_fields.first())
                    .unwrap();
                Self::decrypt_field(item)
            }
        }
    }

    /// Apply filter criteria to narrow down matching item UUIDs.
    /// Returns the subset of UUIDs that pass all filter conditions.
    fn apply_filter<'a>(
        uuids: &[&'a str],
        filter: &SecretFilter,
        items: &[&EnpassItem],
        tags: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<&'a str>> {
        let mut result: Vec<&str> = uuids.to_vec();

        for (key, filter_value) in filter {
            let required_values = filter_value.values();
            let key_lower = key.to_ascii_lowercase();

            result.retain(|uuid| {
                match key_lower.as_str() {
                    "tag" | "tags" | "folder" => {
                        // Match against folder/tag names (AND: all required values must be present)
                        let item_tags = tags.get(*uuid).cloned().unwrap_or_default();
                        let item_tags_lower: Vec<String> =
                            item_tags.iter().map(|t| t.to_ascii_lowercase()).collect();
                        required_values.iter().all(|rv| {
                            item_tags_lower
                                .iter()
                                .any(|t| t == &rv.to_ascii_lowercase())
                        })
                    }
                    "category" => {
                        // Match against item.category
                        let cat = items
                            .iter()
                            .find(|i| i.uuid == *uuid)
                            .map(|i| i.category.to_ascii_lowercase())
                            .unwrap_or_default();
                        required_values
                            .iter()
                            .any(|rv| cat == rv.to_ascii_lowercase())
                    }
                    "favorite" | "fav" => {
                        let is_fav = items.iter().any(|i| i.uuid == *uuid && i.favorite);
                        required_values.iter().any(|rv| {
                            matches!(rv.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
                                == is_fav
                        })
                    }
                    "archived" => {
                        let is_archived = items.iter().any(|i| i.uuid == *uuid && i.archived);
                        required_values.iter().any(|rv| {
                            matches!(rv.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
                                == is_archived
                        })
                    }
                    _ => {
                        // Generic field filter: match against itemfield label/value.
                        // For sensitive (encrypted) fields, decrypt before comparing.
                        items.iter().any(|i| {
                            if i.uuid != *uuid || !i.label.eq_ignore_ascii_case(key) {
                                return false;
                            }
                            let field_value = if i.sensitive {
                                match Self::decrypt_field(i) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        tracing::trace!(
                                            label = %i.label,
                                            uuid = %i.uuid,
                                            error = %e,
                                            "Skipping sensitive field in filter (decryption failed)"
                                        );
                                        return false;
                                    }
                                }
                            } else {
                                i.value.clone()
                            };
                            required_values
                                .iter()
                                .any(|rv| field_value.eq_ignore_ascii_case(rv))
                        })
                    }
                }
            });
        }

        Ok(result)
    }
}

#[async_trait]
impl crate::providers::Provider for EnpassProvider {
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::RemoteRead]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        self.get_secret_filtered(value, None).await
    }

    async fn get_secret_filtered(
        &self,
        value: &str,
        filter: Option<&SecretFilter>,
    ) -> Result<String> {
        tracing::debug!(
            "Getting secret '{}' from Enpass vault (filter: {:?})",
            value,
            filter.is_some()
        );
        let conn = self.open_database()?;
        let items = self.query_items(&conn)?;
        let tags = self.query_tags(&conn)?;
        Self::resolve_from_items_filtered(&items, value, filter, &tags)
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        if secrets.is_empty() {
            return HashMap::new();
        }

        tracing::debug!("Batch fetching {} secrets from Enpass vault", secrets.len());

        // Open database once for all secrets
        let (items, tags) = match self.open_database().and_then(|conn| {
            let items = self.query_items(&conn)?;
            let tags = self.query_tags(&conn)?;
            Ok((items, tags))
        }) {
            Ok(data) => data,
            Err(e) => {
                return secrets
                    .iter()
                    .map(|(key, _)| {
                        (
                            key.clone(),
                            Err(FnoxError::ProviderApiError {
                                provider: PROVIDER.to_string(),
                                details: e.to_string(),
                                hint: "Check your Enpass vault configuration".to_string(),
                                url: URL.to_string(),
                            }),
                        )
                    })
                    .collect();
            }
        };

        // Batch secrets don't have filter info (filtered secrets are resolved individually)
        secrets
            .iter()
            .map(|(key, value)| {
                let result = Self::resolve_from_items_filtered(&items, value, None, &tags);
                (key.clone(), result)
            })
            .collect()
    }

    async fn test_connection(&self) -> Result<()> {
        tracing::debug!("Testing connection to Enpass vault");
        let _conn = self.open_database()?;
        Ok(())
    }
}

/// Load an Enpass keyfile (XML format with hex-encoded key)
fn load_keyfile(path: &std::path::Path) -> Result<Vec<u8>> {
    let content = std::fs::read_to_string(path).map_err(|e| FnoxError::ProviderApiError {
        provider: PROVIDER.to_string(),
        details: format!("Failed to read keyfile '{}': {}", path.display(), e),
        hint: "Check that the keyfile exists and is readable".to_string(),
        url: URL.to_string(),
    })?;

    // Enpass keyfile is XML: <key>hex_encoded_bytes</key>
    // Simple parsing without pulling in an XML crate
    let key_hex = content
        .split("<key>")
        .nth(1)
        .and_then(|s| s.split("</key>").next())
        .map(|s| s.trim())
        .ok_or_else(|| FnoxError::ProviderApiError {
            provider: PROVIDER.to_string(),
            details: "Invalid keyfile format: missing <key> element".to_string(),
            hint: "The keyfile should be an XML file with a <key> element containing hex bytes"
                .to_string(),
            url: URL.to_string(),
        })?;

    hex::decode(key_hex).map_err(|e| FnoxError::ProviderApiError {
        provider: PROVIDER.to_string(),
        details: format!("Failed to decode keyfile hex: {}", e),
        hint: "The keyfile contains invalid hex data".to_string(),
        url: URL.to_string(),
    })
}

fn enpass_password() -> Option<String> {
    env::var("FNOX_ENPASS_PASSWORD")
        .or_else(|_| env::var("ENPASS_PASSWORD"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FilterValue;

    fn make_item(
        uuid: &str,
        title: &str,
        label: &str,
        value: &str,
        sensitive: bool,
        category: &str,
        favorite: bool,
        archived: bool,
    ) -> EnpassItem {
        EnpassItem {
            uuid: uuid.to_string(),
            title: title.to_string(),
            label: label.to_string(),
            value: value.to_string(),
            item_key: if sensitive { vec![0u8; 44] } else { vec![] },
            sensitive,
            trashed: 0,
            deleted: 0,
            category: category.to_string(),
            favorite,
            archived,
        }
    }

    #[test]
    fn test_resolve_from_items_basic() {
        let items = vec![
            make_item(
                "uuid1",
                "My Login",
                "password",
                "secret123",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid1", "My Login", "username", "admin", false, "login", false, false,
            ),
        ];

        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "My Login/password",
            None,
            &HashMap::new(),
        );
        assert_eq!(result.unwrap(), "secret123");

        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "My Login/username",
            None,
            &HashMap::new(),
        );
        assert_eq!(result.unwrap(), "admin");

        // Title-only returns first sensitive field
        let result =
            EnpassProvider::resolve_from_items_filtered(&items, "My Login", None, &HashMap::new());
        assert_eq!(result.unwrap(), "secret123");
    }

    #[test]
    fn test_resolve_from_items_filtered_by_tag() {
        let items = vec![
            make_item(
                "uuid-dev", "Database", "password", "dev-pass", false, "login", false, false,
            ),
            make_item(
                "uuid-prod",
                "Database",
                "password",
                "prod-pass",
                false,
                "login",
                false,
                false,
            ),
        ];

        let mut tags: HashMap<String, Vec<String>> = HashMap::new();
        tags.insert("uuid-dev".to_string(), vec!["DEV".to_string()]);
        tags.insert("uuid-prod".to_string(), vec!["PROD".to_string()]);

        // Filter by tag=DEV → gets dev-pass
        let mut filter = SecretFilter::new();
        filter.insert("tag".to_string(), FilterValue::Single("DEV".to_string()));
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "Database/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "dev-pass");

        // Filter by tag=PROD → gets prod-pass
        let mut filter = SecretFilter::new();
        filter.insert("tag".to_string(), FilterValue::Single("PROD".to_string()));
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "Database/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "prod-pass");
    }

    #[test]
    fn test_resolve_from_items_ambiguity_error() {
        let items = vec![
            make_item(
                "uuid-a", "Database", "password", "pass-a", false, "login", false, false,
            ),
            make_item(
                "uuid-b", "Database", "password", "pass-b", false, "login", false, false,
            ),
        ];

        let tags: HashMap<String, Vec<String>> = HashMap::new();

        // Without filter, first match wins (backward compat)
        let result =
            EnpassProvider::resolve_from_items_filtered(&items, "Database/password", None, &tags);
        assert!(result.is_ok());

        // With filter but still ambiguous → error
        let mut filter = SecretFilter::new();
        filter.insert(
            "category".to_string(),
            FilterValue::Single("login".to_string()),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "Database/password",
            Some(&filter),
            &tags,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Multiple items named"), "Error: {}", err);
    }

    #[test]
    fn test_resolve_from_items_filter_by_category() {
        let items = vec![
            make_item(
                "uuid-login",
                "MyApp",
                "password",
                "login-pass",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-note",
                "MyApp",
                "password",
                "note-pass",
                false,
                "note",
                false,
                false,
            ),
        ];

        let tags: HashMap<String, Vec<String>> = HashMap::new();
        let mut filter = SecretFilter::new();
        filter.insert(
            "category".to_string(),
            FilterValue::Single("note".to_string()),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "MyApp/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "note-pass");
    }

    #[test]
    fn test_resolve_from_items_filter_by_favorite() {
        let items = vec![
            make_item(
                "uuid-fav", "Secret", "password", "fav-pass", false, "login", true, false,
            ),
            make_item(
                "uuid-nofav",
                "Secret",
                "password",
                "nofav-pass",
                false,
                "login",
                false,
                false,
            ),
        ];

        let tags: HashMap<String, Vec<String>> = HashMap::new();
        let mut filter = SecretFilter::new();
        filter.insert(
            "favorite".to_string(),
            FilterValue::Single("true".to_string()),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "Secret/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "fav-pass");
    }

    #[test]
    fn test_resolve_from_items_multi_tag_filter() {
        let items = vec![
            make_item(
                "uuid-both",
                "API",
                "password",
                "both-pass",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-one", "API", "password", "one-pass", false, "login", false, false,
            ),
        ];

        let mut tags: HashMap<String, Vec<String>> = HashMap::new();
        tags.insert(
            "uuid-both".to_string(),
            vec!["backend".to_string(), "prod".to_string()],
        );
        tags.insert("uuid-one".to_string(), vec!["backend".to_string()]);

        // Multi-tag filter: must have BOTH tags
        let mut filter = SecretFilter::new();
        filter.insert(
            "tag".to_string(),
            FilterValue::Multiple(vec!["backend".to_string(), "prod".to_string()]),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "API/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "both-pass");
    }

    #[test]
    fn test_resolve_from_items_filter_by_field() {
        let items = vec![
            make_item(
                "uuid-admin",
                "Database",
                "username",
                "admin",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-admin",
                "Database",
                "password",
                "admin-pass",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-ro", "Database", "username", "readonly", false, "login", false, false,
            ),
            make_item(
                "uuid-ro", "Database", "password", "ro-pass", false, "login", false, false,
            ),
        ];

        let tags: HashMap<String, Vec<String>> = HashMap::new();

        // Filter by Username=admin → gets admin-pass
        let mut filter = SecretFilter::new();
        filter.insert(
            "Username".to_string(),
            FilterValue::Single("admin".to_string()),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "Database/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "admin-pass");

        // Filter by Username=readonly → gets ro-pass
        let mut filter = SecretFilter::new();
        filter.insert(
            "Username".to_string(),
            FilterValue::Single("readonly".to_string()),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "Database/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "ro-pass");
    }

    #[test]
    fn test_resolve_from_items_filter_by_field_case_insensitive() {
        let items = vec![
            make_item(
                "uuid-a",
                "Server",
                "URL",
                "https://prod.example.com",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-a",
                "Server",
                "password",
                "prod-pass",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-b",
                "Server",
                "URL",
                "https://dev.example.com",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-b", "Server", "password", "dev-pass", false, "login", false, false,
            ),
        ];

        let tags: HashMap<String, Vec<String>> = HashMap::new();

        // Case-insensitive key match
        let mut filter = SecretFilter::new();
        filter.insert(
            "url".to_string(),
            FilterValue::Single("https://prod.example.com".to_string()),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "Server/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "prod-pass");
    }

    #[test]
    fn test_resolve_from_items_filter_by_field_no_match() {
        let items = vec![
            make_item(
                "uuid-a", "App", "username", "alice", false, "login", false, false,
            ),
            make_item(
                "uuid-a",
                "App",
                "password",
                "alice-pass",
                false,
                "login",
                false,
                false,
            ),
        ];

        let tags: HashMap<String, Vec<String>> = HashMap::new();

        // Filter by a field value that doesn't exist
        let mut filter = SecretFilter::new();
        filter.insert(
            "username".to_string(),
            FilterValue::Single("bob".to_string()),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "App/password",
            Some(&filter),
            &tags,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found") || err.contains("No items named"),
            "Error: {}",
            err
        );
    }

    #[test]
    fn test_resolve_from_items_filter_by_field_combined_with_tag() {
        let items = vec![
            make_item(
                "uuid-dev-admin",
                "DB",
                "username",
                "admin",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-dev-admin",
                "DB",
                "password",
                "dev-admin-pass",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-prod-admin",
                "DB",
                "username",
                "admin",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-prod-admin",
                "DB",
                "password",
                "prod-admin-pass",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-prod-ro",
                "DB",
                "username",
                "readonly",
                false,
                "login",
                false,
                false,
            ),
            make_item(
                "uuid-prod-ro",
                "DB",
                "password",
                "prod-ro-pass",
                false,
                "login",
                false,
                false,
            ),
        ];

        let mut tags: HashMap<String, Vec<String>> = HashMap::new();
        tags.insert("uuid-dev-admin".to_string(), vec!["DEV".to_string()]);
        tags.insert("uuid-prod-admin".to_string(), vec!["PROD".to_string()]);
        tags.insert("uuid-prod-ro".to_string(), vec!["PROD".to_string()]);

        // Filter by tag=PROD AND username=admin → gets prod-admin-pass
        let mut filter = SecretFilter::new();
        filter.insert("tag".to_string(), FilterValue::Single("PROD".to_string()));
        filter.insert(
            "username".to_string(),
            FilterValue::Single("admin".to_string()),
        );
        let result = EnpassProvider::resolve_from_items_filtered(
            &items,
            "DB/password",
            Some(&filter),
            &tags,
        );
        assert_eq!(result.unwrap(), "prod-admin-pass");
    }
}
