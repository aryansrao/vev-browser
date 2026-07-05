//! Vev extensions: an honest content-script subset of Chrome extensions.
//!
//! CEF 149's Alloy runtime has no Chrome-extension runtime (upstream removed
//! Alloy extension support), so background pages / service workers / popups /
//! chrome.* APIs cannot exist here. What CAN work — and what a large class of
//! real extensions (dark-mode, CSS restylers, userscript-style helpers) only
//! need — is the content-script half of the manifest: `js`/`css` injected
//! into matching pages at `document_start` or `document_end`. That subset is
//! implemented natively: unpacked extensions are loaded from
//! `<appdata>/extensions/<dir>/manifest.json` (MV2 or MV3 shape), match
//! patterns are evaluated per navigation, and matching scripts/styles are
//! injected by the browser process. The UI labels the limitation explicitly.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Clone, Copy, PartialEq)]
pub enum RunAt {
    DocumentStart,
    DocumentEnd,
}

#[derive(Deserialize)]
struct ManifestContentScript {
    #[serde(default)]
    matches: Vec<String>,
    #[serde(default)]
    exclude_matches: Vec<String>,
    #[serde(default)]
    js: Vec<String>,
    #[serde(default)]
    css: Vec<String>,
    #[serde(default)]
    run_at: Option<String>,
}

#[derive(Deserialize)]
struct Manifest {
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    manifest_version: u32,
    #[serde(default)]
    content_scripts: Vec<ManifestContentScript>,
}

/// One loaded content script, sources read into memory at load time.
struct ContentScript {
    matches: Vec<String>,
    exclude_matches: Vec<String>,
    js: Vec<String>,
    css: Vec<String>,
    run_at: RunAt,
}

struct Extension {
    id: String, // directory name
    name: String,
    version: String,
    description: String,
    manifest_version: u32,
    enabled: bool,
    scripts: Vec<ContentScript>,
}

#[derive(Clone, Serialize)]
pub struct ExtensionInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub manifest_version: u32,
    pub enabled: bool,
    pub content_script_count: usize,
}

static REGISTRY: RwLock<Vec<Extension>> = RwLock::new(Vec::new());
static DIR: RwLock<Option<PathBuf>> = RwLock::new(None);

#[derive(Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default)]
    disabled: Vec<String>,
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("extensions.json")
}

/// Chrome match-pattern check: `<all_urls>` or `scheme://host/path` where
/// scheme may be `*` (http/https), host may be `*` or `*.domain`, and the
/// path may contain `*` wildcards.
pub fn pattern_matches(pattern: &str, url: &str) -> bool {
    if pattern == "<all_urls>" {
        return url.starts_with("http://")
            || url.starts_with("https://")
            || url.starts_with("file://");
    }
    let Some((p_scheme, rest)) = pattern.split_once("://") else {
        return false;
    };
    let (p_host, p_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/*"),
    };
    let Ok(u) = url::Url::parse(url) else {
        return false;
    };
    match p_scheme {
        "*" => {
            if u.scheme() != "http" && u.scheme() != "https" {
                return false;
            }
        }
        s => {
            if u.scheme() != s {
                return false;
            }
        }
    }
    let host = u.host_str().unwrap_or("");
    let host_ok = match p_host {
        "*" => true,
        p if p.starts_with("*.") => {
            let base = &p[2..];
            host == base || host.ends_with(&format!(".{base}"))
        }
        p => host == p,
    };
    if !host_ok {
        return false;
    }
    // Path (+query) with '*' wildcards.
    let mut path = u.path().to_string();
    if let Some(q) = u.query() {
        path.push('?');
        path.push_str(q);
    }
    glob_match(p_path, &path)
}

/// Minimal '*' glob matcher (no character classes — Chrome patterns only
/// use '*').
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Iterative wildcard match, O(len_p * len_t) worst case.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn load_one(dir: &Path, disabled: &[String]) -> Option<Extension> {
    let id = dir.file_name()?.to_string_lossy().to_string();
    let manifest_bytes = std::fs::read(dir.join("manifest.json")).ok()?;
    let m: Manifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("vev-ext: {id}: bad manifest.json: {e}");
            return None;
        }
    };
    let mut scripts = Vec::new();
    for cs in &m.content_scripts {
        let read_all = |files: &[String]| -> Vec<String> {
            files
                .iter()
                .filter_map(|f| {
                    // Forbid path escapes out of the extension dir.
                    if f.contains("..") {
                        return None;
                    }
                    match std::fs::read_to_string(dir.join(f.trim_start_matches('/'))) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            eprintln!("vev-ext: {id}: cannot read {f}: {e}");
                            None
                        }
                    }
                })
                .collect()
        };
        scripts.push(ContentScript {
            matches: cs.matches.clone(),
            exclude_matches: cs.exclude_matches.clone(),
            js: read_all(&cs.js),
            css: read_all(&cs.css),
            run_at: match cs.run_at.as_deref() {
                Some("document_start") => RunAt::DocumentStart,
                // document_end, document_idle, unspecified → after load.
                _ => RunAt::DocumentEnd,
            },
        });
    }
    Some(Extension {
        enabled: !disabled.contains(&id),
        id,
        name: m.name,
        version: m.version,
        description: m.description,
        manifest_version: m.manifest_version,
        scripts,
    })
}

/// Scan the extensions dir and (re)build the registry.
pub fn reload() {
    let Some(dir) = DIR.read().unwrap().clone() else { return };
    let state: StateFile = std::fs::read(state_path(&dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let mut exts = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() && p.join("manifest.json").exists() {
                if let Some(ext) = load_one(&p, &state.disabled) {
                    exts.push(ext);
                }
            }
        }
    }
    exts.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    eprintln!("vev-ext: {} extension(s) loaded", exts.len());
    *REGISTRY.write().unwrap() = exts;
}

pub fn init(data_dir: &Path) {
    let dir = data_dir.join("extensions");
    let _ = std::fs::create_dir_all(&dir);
    *DIR.write().unwrap() = Some(dir);
    reload();
}

pub fn list() -> Vec<ExtensionInfo> {
    REGISTRY
        .read()
        .unwrap()
        .iter()
        .map(|e| ExtensionInfo {
            id: e.id.clone(),
            name: e.name.clone(),
            version: e.version.clone(),
            description: e.description.clone(),
            manifest_version: e.manifest_version,
            enabled: e.enabled,
            content_script_count: e.scripts.len(),
        })
        .collect()
}

fn save_state() {
    let Some(dir) = DIR.read().unwrap().clone() else { return };
    let disabled: Vec<String> = REGISTRY
        .read()
        .unwrap()
        .iter()
        .filter(|e| !e.enabled)
        .map(|e| e.id.clone())
        .collect();
    let _ = std::fs::write(
        state_path(&dir),
        serde_json::to_vec_pretty(&StateFile { disabled }).unwrap_or_default(),
    );
}

pub fn set_enabled(id: &str, enabled: bool) -> Result<(), String> {
    {
        let mut reg = REGISTRY.write().unwrap();
        let ext = reg
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| format!("no extension '{id}'"))?;
        ext.enabled = enabled;
    }
    save_state();
    Ok(())
}

/// Install an unpacked extension by copying `src_dir` (must contain
/// manifest.json) into the extensions dir. Returns the new extension id.
pub fn install(src_dir: &str) -> Result<String, String> {
    let src = PathBuf::from(shellexpand_home(src_dir));
    if !src.join("manifest.json").exists() {
        return Err("folder has no manifest.json".into());
    }
    // Validate the manifest parses before copying anything.
    let bytes = std::fs::read(src.join("manifest.json")).map_err(|e| e.to_string())?;
    let m: Manifest =
        serde_json::from_slice(&bytes).map_err(|e| format!("manifest.json: {e}"))?;
    if m.content_scripts.is_empty() {
        return Err(format!(
            "'{}' declares no content_scripts — Vev runs the content-script \
             subset (background pages/popups need the full Chrome runtime, \
             which the embedded engine does not provide)",
            m.name
        ));
    }
    let dir = DIR
        .read()
        .unwrap()
        .clone()
        .ok_or("extensions not initialized")?;
    let id = src
        .file_name()
        .ok_or("bad source folder")?
        .to_string_lossy()
        .to_string();
    let dest = dir.join(&id);
    copy_dir(&src, &dest).map_err(|e| format!("copy: {e}"))?;
    reload();
    Ok(id)
}

pub fn uninstall(id: &str) -> Result<(), String> {
    // Refuse path tricks in the id.
    if id.contains('/') || id.contains("..") {
        return Err("bad extension id".into());
    }
    let dir = DIR
        .read()
        .unwrap()
        .clone()
        .ok_or("extensions not initialized")?;
    std::fs::remove_dir_all(dir.join(id)).map_err(|e| e.to_string())?;
    reload();
    Ok(())
}

fn shellexpand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{rest}", home.to_string_lossy());
        }
    }
    p.to_string()
}

fn copy_dir(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for e in std::fs::read_dir(src)?.flatten() {
        let ty = e.file_type()?;
        let to = dest.join(e.file_name());
        if ty.is_dir() {
            copy_dir(&e.path(), &to)?;
        } else if ty.is_file() {
            std::fs::copy(e.path(), &to)?;
        }
    }
    Ok(())
}

/// Inject matching enabled content scripts into `frame` for `url` at the
/// given phase. Main thread (CEF UI thread) only.
pub fn inject(frame: &mut cef::Frame, url: &str, phase: RunAt) {
    use cef::ImplFrame;
    if !(url.starts_with("http") || url.starts_with("file:")) {
        return;
    }
    let reg = REGISTRY.read().unwrap();
    for ext in reg.iter().filter(|e| e.enabled) {
        for cs in &ext.scripts {
            if cs.run_at != phase {
                continue;
            }
            let included = cs.matches.iter().any(|p| pattern_matches(p, url));
            let excluded = cs
                .exclude_matches
                .iter()
                .any(|p| pattern_matches(p, url));
            if !included || excluded {
                continue;
            }
            for css in &cs.css {
                let escaped = css.replace('\\', "\\\\").replace('`', "\\`");
                let js = format!(
                    "(function(){{try{{var s=document.createElement('style');\
                     s.setAttribute('data-vev-ext','{}');s.textContent=`{escaped}`;\
                     (document.head||document.documentElement).appendChild(s);}}\
                     catch(e){{}}}})();",
                    ext.id
                );
                frame.execute_java_script(
                    Some(&cef::CefString::from(js.as_str())),
                    Some(&cef::CefString::from(
                        format!("vev-ext://{}/css", ext.id).as_str(),
                    )),
                    0,
                );
            }
            for js in &cs.js {
                frame.execute_java_script(
                    Some(&cef::CefString::from(js.as_str())),
                    Some(&cef::CefString::from(
                        format!("vev-ext://{}", ext.id).as_str(),
                    )),
                    0,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_patterns() {
        assert!(pattern_matches("<all_urls>", "https://a.example/x"));
        assert!(!pattern_matches("<all_urls>", "chrome://settings"));
        assert!(pattern_matches("*://*/*", "https://a.example/x?y=1"));
        assert!(pattern_matches("*://*/*", "http://a.example/"));
        assert!(!pattern_matches("*://*/*", "file:///tmp/x.html"));
        assert!(pattern_matches(
            "https://*.youtube.com/watch*",
            "https://www.youtube.com/watch?v=abc"
        ));
        assert!(!pattern_matches(
            "https://*.youtube.com/watch*",
            "https://youtube.evil.com/watch?v=abc"
        ));
        assert!(pattern_matches(
            "https://youtube.com/*",
            "https://youtube.com/feed"
        ));
        assert!(!pattern_matches(
            "https://example.com/exact",
            "https://example.com/exact/deeper"
        ));
        assert!(pattern_matches(
            "https://example.com/a/*/b",
            "https://example.com/a/x/y/b"
        ));
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match("/*", "/anything/at/all"));
        assert!(glob_match("/watch*", "/watch?v=1"));
        assert!(!glob_match("/watch", "/watchx"));
        assert!(glob_match("*", ""));
    }
}
