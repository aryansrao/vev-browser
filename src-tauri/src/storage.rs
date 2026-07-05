//! App-side wrapper around the encrypted `vev-storage` store: shared,
//! mutex-guarded, and migrates the Phase 1 plaintext bookmarks on first open.

use std::path::PathBuf;
use std::sync::Mutex;
use tauri::Manager;
use vev_storage::{Bookmark, EncryptedStore, PasswordEntry};

pub struct Storage {
    inner: Mutex<EncryptedStore>,
}

impl Storage {
    pub fn open(app: &tauri::AppHandle) -> Result<Self, String> {
        let dir = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("app data dir: {e}"))?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
        let path = dir.join("vault.enc");
        let mut store = EncryptedStore::open(&path)?;

        // One-time migration of plaintext bookmarks.json -> encrypted vault.
        let legacy: PathBuf = dir.join("bookmarks.json");
        if legacy.exists() {
            if let Ok(bytes) = std::fs::read(&legacy) {
                if let Ok(items) = serde_json::from_slice::<Vec<LegacyBookmark>>(&bytes) {
                    for b in items {
                        let _ = store.add_bookmark(b.url, b.title);
                    }
                }
            }
            // Remove the plaintext file so secrets no longer sit in the clear.
            let _ = std::fs::remove_file(&legacy);
            eprintln!("vev-storage: migrated legacy bookmarks.json into encrypted vault");
        }

        Ok(Self {
            inner: Mutex::new(store),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, EncryptedStore>, String> {
        self.inner.lock().map_err(|_| "storage lock poisoned".into())
    }

    pub fn bookmarks(&self) -> Result<Vec<Bookmark>, String> {
        Ok(self.lock()?.bookmarks().to_vec())
    }

    pub fn add_bookmark(&self, url: String, title: String) -> Result<Vec<Bookmark>, String> {
        let mut s = self.lock()?;
        s.add_bookmark(url, title)?;
        Ok(s.bookmarks().to_vec())
    }

    pub fn remove_bookmark(&self, url: &str) -> Result<Vec<Bookmark>, String> {
        let mut s = self.lock()?;
        s.remove_bookmark(url)?;
        Ok(s.bookmarks().to_vec())
    }

    pub fn add_history(&self, url: String, title: String) {
        if let Ok(mut s) = self.lock() {
            let _ = s.add_history(url, title);
        }
    }

    pub fn history(&self, limit: usize) -> Vec<vev_storage::HistoryEntry> {
        self.lock().map(|s| s.history(limit)).unwrap_or_default()
    }

    pub fn passwords_for(&self, origin: &str) -> Result<Vec<PasswordEntry>, String> {
        Ok(self.lock()?.passwords_for(origin))
    }

    pub fn history_clear(&self) -> Result<(), String> {
        self.lock()?.clear_history()
    }

    pub fn history_delete(&self, url: &str) -> Result<(), String> {
        self.lock()?.delete_history(url)
    }

    pub fn passwords_all(&self) -> Result<Vec<PasswordEntry>, String> {
        Ok(self.lock()?.passwords_all())
    }

    pub fn passwords_delete(&self, origin: &str, username: &str) -> Result<(), String> {
        self.lock()?.delete_password(origin, username)
    }

    pub fn save_password(
        &self,
        origin: String,
        username: String,
        password: String,
    ) -> Result<(), String> {
        self.lock()?.save_password(origin, username, password)
    }
}

#[derive(serde::Deserialize)]
struct LegacyBookmark {
    url: String,
    title: String,
    #[allow(dead_code)]
    #[serde(default)]
    added_unix: u64,
}
