//! Pane state. Local pane: real filesystem via `std::fs`. Remote pane: wired
//! to the SDK in M3/M7 (depends on auth + http impl landing together).

use std::path::{Path, PathBuf};

use proton_drive::NodeUid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Local,
    Remote,
}

#[derive(Debug, Clone)]
pub struct PaneEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: Option<u64>,
    pub selected: bool,
    /// Remote node UID — `Some` only for entries in the remote pane.
    pub node_uid: Option<NodeUid>,
}

#[derive(Debug, Default)]
pub struct Pane {
    pub cwd: PathBuf,
    pub entries: Vec<PaneEntry>,
    pub cursor: usize,
    /// Surfaced to the status bar when set.
    pub error: Option<String>,
    /// For the remote pane: the NodeUid of the directory currently displayed.
    /// `None` until authenticated and listed.
    pub remote_cwd_uid: Option<NodeUid>,
}

pub struct Panes {
    pub local: Pane,
    pub remote: Pane,
}

impl Panes {
    pub fn new() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        let mut local = Pane {
            cwd: cwd.clone(),
            ..Default::default()
        };
        local.load_local();
        Self {
            local,
            remote: Pane {
                cwd: PathBuf::from("/"),
                error: Some("Not signed in — press Enter or F4 to login".into()),
                ..Default::default()
            },
        }
    }

    fn at_mut(&mut self, focus: Focus) -> &mut Pane {
        match focus {
            Focus::Local => &mut self.local,
            Focus::Remote => &mut self.remote,
        }
    }

    pub fn cursor_up(&mut self, focus: Focus) {
        let p = self.at_mut(focus);
        p.cursor = p.cursor.saturating_sub(1);
    }

    pub fn cursor_down(&mut self, focus: Focus) {
        let p = self.at_mut(focus);
        if p.cursor + 1 < p.entries.len() {
            p.cursor += 1;
        }
    }

    pub fn descend(&mut self, focus: Focus) {
        if !matches!(focus, Focus::Local) {
            return;
        }
        let p = self.at_mut(focus);
        let Some(entry) = p.entries.get(p.cursor).cloned() else {
            return;
        };
        if !entry.is_dir {
            return;
        }
        let target = if entry.name == ".." {
            p.cwd.parent().unwrap_or(&p.cwd).to_path_buf()
        } else {
            p.cwd.join(&entry.name)
        };
        p.cwd = target;
        p.cursor = 0;
        p.load_local();
    }

    pub fn ascend(&mut self, focus: Focus) {
        if !matches!(focus, Focus::Local) {
            return;
        }
        let p = self.at_mut(focus);
        if let Some(parent) = p.cwd.parent() {
            p.cwd = parent.to_path_buf();
            p.cursor = 0;
            p.load_local();
        }
    }

    pub fn refresh(&mut self, focus: Focus) {
        if matches!(focus, Focus::Local) {
            self.local.load_local();
        }
    }

    pub fn toggle_select(&mut self, focus: Focus) {
        let p = self.at_mut(focus);
        if let Some(e) = p.entries.get_mut(p.cursor) {
            e.selected = !e.selected;
        }
    }

    /// Return the absolute path of the locally selected file.
    ///
    /// Returns `None` if the cursor is on a directory or the ".." entry.
    pub fn selected_local_path(&self) -> Option<PathBuf> {
        let entry = self.local.entries.get(self.local.cursor)?;
        if entry.is_dir {
            return None;
        }
        Some(self.local.cwd.join(&entry.name))
    }

    /// Return absolute paths of all space-bar-marked local files.
    ///
    /// Skips directories and the ".." entry. Returns an empty `Vec` if nothing
    /// is marked.
    pub fn marked_local_paths(&self) -> Vec<PathBuf> {
        self.local
            .entries
            .iter()
            .filter(|e| e.selected && !e.is_dir)
            .map(|e| self.local.cwd.join(&e.name))
            .collect()
    }

    /// Clear the `selected` flag on every local-pane entry.
    pub fn clear_local_marks(&mut self) {
        for e in &mut self.local.entries {
            e.selected = false;
        }
    }

    /// Return `(NodeUid, name)` of the currently selected remote file.
    ///
    /// Returns `None` if the cursor is on a directory, the entry has no node
    /// UID (not yet loaded), or the remote pane has an error.
    pub fn selected_remote_node(&self) -> Option<(NodeUid, String)> {
        if self.remote.error.is_some() {
            return None;
        }
        let entry = self.remote.entries.get(self.remote.cursor)?;
        if entry.is_dir {
            return None;
        }
        let uid = entry.node_uid.clone()?;
        Some((uid, entry.name.clone()))
    }

    /// Return the `NodeUid` for the remote folder currently shown.
    ///
    /// Returns `None` if the remote pane has not yet been loaded (pre-login).
    pub fn remote_folder_uid(&self) -> Option<&NodeUid> {
        self.remote.remote_cwd_uid.as_ref()
    }
}

impl Default for Panes {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane {
    /// Populate `entries` from the local filesystem at `cwd`. Errors surface
    /// to `error` rather than panicking — we never lose the UI to an I/O blip.
    pub fn load_local(&mut self) {
        self.error = None;
        match list_dir(&self.cwd) {
            Ok(mut entries) => {
                // Sort: parent first, then directories (alpha), then files (alpha).
                entries.sort_by(|a, b| match (a.name == "..", b.name == "..") {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => match (a.is_dir, b.is_dir) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => a.name.cmp(&b.name),
                    },
                });
                self.entries = entries;
                if self.cursor >= self.entries.len() {
                    self.cursor = self.entries.len().saturating_sub(1);
                }
            }
            Err(e) => {
                self.entries.clear();
                self.error = Some(format!("{}: {e}", self.cwd.display()));
            }
        }
    }
}

fn list_dir(p: &Path) -> std::io::Result<Vec<PaneEntry>> {
    let mut out: Vec<PaneEntry> = Vec::new();
    if p.parent().is_some() {
        out.push(PaneEntry {
            name: "..".into(),
            is_dir: true,
            size_bytes: None,
            selected: false,
            node_uid: None,
        });
    }
    for entry in std::fs::read_dir(p)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Hide dotfiles by default — M7 will add a toggle.
        if name.starts_with('.') {
            continue;
        }
        let is_dir = meta.is_dir();
        let size_bytes = if is_dir { None } else { Some(meta.len()) };
        out.push(PaneEntry {
            name,
            is_dir,
            size_bytes,
            selected: false,
            node_uid: None,
        });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn loads_real_directory() {
        let tmp = std::env::temp_dir().join(format!("pdtui-test-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::create_dir_all(tmp.join("subdir")).unwrap();
        fs::write(tmp.join("file.txt"), b"hello").unwrap();
        let mut p = Pane {
            cwd: tmp.clone(),
            ..Default::default()
        };
        p.load_local();
        assert!(p.error.is_none(), "{:?}", p.error);
        assert!(p.entries.iter().any(|e| e.name == "subdir" && e.is_dir));
        assert!(p.entries.iter().any(|e| e.name == "file.txt" && !e.is_dir));
        // Parent ".." sorted first.
        assert_eq!(p.entries.first().map(|e| e.name.as_str()), Some(".."));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn nonexistent_dir_sets_error() {
        let mut p = Pane {
            cwd: PathBuf::from("/this/path/does/not/exist/pdtui"),
            ..Default::default()
        };
        p.load_local();
        assert!(p.error.is_some());
        assert!(p.entries.is_empty());
    }
}
