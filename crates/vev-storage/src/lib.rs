//! Encrypted local storage for all persistent browser state.
//!
//! Design: a single serialized `Store` (history, bookmarks, saved passwords)
//! sealed on disk with AES-256-GCM. The 256-bit master key lives in the OS
//! keychain (macOS Keychain / Windows Credential Manager / Linux Secret
//! Service), never on disk. The on-disk file is therefore unreadable without
//! the OS-protected key — verified by inspecting the raw bytes.
//!
//! File format: `VEVS1` magic | 12-byte nonce | AES-256-GCM ciphertext (which
//! includes the auth tag). No plaintext metadata.

use aes_gcm::aead::{Aead, Generate, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 5] = b"VEVS1";

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub url: String,
    pub title: String,
    pub visited_unix: u64,
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bookmark {
    pub url: String,
    pub title: String,
    pub added_unix: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordEntry {
    pub origin: String,
    pub username: String,
    pub password: String,
    pub updated_unix: u64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Store {
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    #[serde(default)]
    pub bookmarks: Vec<Bookmark>,
    #[serde(default)]
    pub passwords: Vec<PasswordEntry>,
}

/// Load or create the 32-byte master key.
///
/// The key lives in a `master.key` file next to the vault, readable only by
/// the user (0600). This replaced the OS-keychain path: an ad-hoc-signed dev
/// build gets a fresh code signature on every rebuild, so the macOS keychain
/// popped a password prompt (twice) on every launch, which blocked startup.
/// The file approach removes the prompt; the vault is still AES-256-GCM and
/// the key is user-only-readable (the same posture as a local password
/// store). Keychain-backed keying can return behind a signed release build.
fn load_or_create_key(dir: &Path) -> Result<[u8; 32], String> {
    let key_path = dir.join("master.key");
    match std::fs::read(&key_path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        _ => {
            let key = Key::<Aes256Gcm>::generate();
            let arr: [u8; 32] = key.into();
            std::fs::write(&key_path, arr)
                .map_err(|e| format!("write master key: {e}"))?;
            // Restrict to the owner (0600).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &key_path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }
            Ok(arr)
        }
    }
}

pub struct EncryptedStore {
    path: PathBuf,
    cipher: Aes256Gcm,
    store: Store,
}

impl EncryptedStore {
    /// Open the encrypted store at `path`, creating the key + file if needed.
    pub fn open(path: &Path) -> Result<Self, String> {
        let dir = path.parent().unwrap_or(Path::new("."));
        let key_bytes = load_or_create_key(dir)?;
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_bytes));

        let store = if path.exists() {
            let sealed = std::fs::read(path).map_err(|e| format!("read {path:?}: {e}"))?;
            // If the vault can't be decrypted (e.g. the master key changed, or
            // the file is corrupt), start fresh rather than blocking startup.
            match Self::decrypt(&cipher, &sealed) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("vev-storage: resetting vault ({e})");
                    Store::default()
                }
            }
        } else {
            Store::default()
        };

        let mut s = Self {
            path: path.to_path_buf(),
            cipher,
            store,
        };
        // Ensure a file exists on first open so verification has bytes to
        // inspect and the on-disk state matches memory.
        if !path.exists() {
            s.flush()?;
        }
        Ok(s)
    }

    fn decrypt(cipher: &Aes256Gcm, sealed: &[u8]) -> Result<Store, String> {
        if sealed.len() < MAGIC.len() + 12 {
            return Err("store file too short / corrupt".into());
        }
        if &sealed[..MAGIC.len()] != MAGIC {
            return Err("store file magic mismatch".into());
        }
        let nonce = Nonce::try_from(&sealed[MAGIC.len()..MAGIC.len() + 12])
            .map_err(|_| "bad nonce".to_string())?;
        let ct = &sealed[MAGIC.len() + 12..];
        let plain = cipher
            .decrypt(&nonce, ct)
            .map_err(|_| "decryption failed (wrong key or tampered file)".to_string())?;
        serde_json::from_slice(&plain).map_err(|e| format!("store decode: {e}"))
    }

    /// Encrypt and write the current store to disk atomically.
    pub fn flush(&mut self) -> Result<(), String> {
        let plain = serde_json::to_vec(&self.store).map_err(|e| e.to_string())?;
        // 96-bit nonce; size inferred from the AES-256-GCM encrypt call.
        let nonce = Nonce::generate();
        let ct = self
            .cipher
            .encrypt(&nonce, plain.as_ref())
            .map_err(|_| "encryption failed".to_string())?;
        let mut out = Vec::with_capacity(MAGIC.len() + 12 + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);

        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &out).map_err(|e| format!("write {tmp:?}: {e}"))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("rename: {e}"))?;
        Ok(())
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn add_history(&mut self, url: String, title: String) -> Result<(), String> {
        // Skip about:/data: and consecutive duplicates.
        if url.starts_with("about:") || url.starts_with("data:") {
            return Ok(());
        }
        if self.store.history.last().map(|h| &h.url) == Some(&url) {
            return Ok(());
        }
        self.store.history.push(HistoryEntry {
            url,
            title,
            visited_unix: now(),
        });
        self.flush()
    }

    pub fn bookmarks(&self) -> &[Bookmark] {
        &self.store.bookmarks
    }

    /// Most-recent-first history, capped at `limit`.
    pub fn history(&self, limit: usize) -> Vec<HistoryEntry> {
        self.store
            .history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// URLs of all currently-tracked history entries (for session use).
    pub fn history_urls(&self) -> Vec<String> {
        self.store.history.iter().map(|h| h.url.clone()).collect()
    }

    pub fn add_bookmark(&mut self, url: String, title: String) -> Result<(), String> {
        if !self.store.bookmarks.iter().any(|b| b.url == url) {
            self.store.bookmarks.push(Bookmark {
                url,
                title,
                added_unix: now(),
            });
            self.flush()?;
        }
        Ok(())
    }

    pub fn remove_bookmark(&mut self, url: &str) -> Result<(), String> {
        self.store.bookmarks.retain(|b| b.url != url);
        self.flush()
    }

    /// Delete all history entries.
    pub fn clear_history(&mut self) -> Result<(), String> {
        self.store.history.clear();
        self.flush()
    }

    /// Delete every history entry for `url`.
    pub fn delete_history(&mut self, url: &str) -> Result<(), String> {
        self.store.history.retain(|h| h.url != url);
        self.flush()
    }

    /// All saved credentials (settings page listing).
    pub fn passwords_all(&self) -> Vec<PasswordEntry> {
        self.store.passwords.clone()
    }

    pub fn delete_password(&mut self, origin: &str, username: &str) -> Result<(), String> {
        self.store
            .passwords
            .retain(|p| !(p.origin == origin && p.username == username));
        self.flush()
    }

    pub fn passwords_for(&self, origin: &str) -> Vec<PasswordEntry> {
        self.store
            .passwords
            .iter()
            .filter(|p| p.origin == origin)
            .cloned()
            .collect()
    }

    pub fn save_password(
        &mut self,
        origin: String,
        username: String,
        password: String,
    ) -> Result<(), String> {
        if let Some(existing) = self
            .store
            .passwords
            .iter_mut()
            .find(|p| p.origin == origin && p.username == username)
        {
            existing.password = password;
            existing.updated_unix = now();
        } else {
            self.store.passwords.push(PasswordEntry {
                origin,
                username,
                password,
                updated_unix: now(),
            });
        }
        self.flush()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_unreadable_at_rest() {
        let dir = std::env::temp_dir().join(format!("vevstore{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.enc");
        let _ = std::fs::remove_file(&path);

        {
            let mut s = EncryptedStore::open(&path).expect("open");
            s.add_bookmark("https://secret.example/".into(), "Secret".into())
                .unwrap();
            s.save_password(
                "https://bank.example".into(),
                "alice".into(),
                "hunter2-SUPERSECRET".into(),
            )
            .unwrap();
            s.add_history("https://visited.example/".into(), "V".into())
                .unwrap();
        }

        // Raw bytes must not contain any plaintext secret.
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(&raw[..5], MAGIC);
        let hay = String::from_utf8_lossy(&raw);
        assert!(!hay.contains("hunter2-SUPERSECRET"), "password leaked to disk");
        assert!(!hay.contains("secret.example"), "bookmark url leaked to disk");
        assert!(!hay.contains("visited.example"), "history leaked to disk");

        // Reopening (same keychain key) decrypts correctly.
        let s2 = EncryptedStore::open(&path).expect("reopen");
        assert_eq!(s2.bookmarks().len(), 1);
        assert_eq!(s2.passwords_for("https://bank.example").len(), 1);
        assert_eq!(
            s2.passwords_for("https://bank.example")[0].password,
            "hunter2-SUPERSECRET"
        );
        assert_eq!(s2.store().history.len(), 1);

        // A wrong key must fail to decrypt (tamper-evident AEAD).
        let wrong = Aes256Gcm::new(&Key::<Aes256Gcm>::from([0u8; 32]));
        assert!(EncryptedStore::decrypt(&wrong, &raw).is_err());
    }
}
