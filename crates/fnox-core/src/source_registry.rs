//! Global registry of config file sources for error reporting with miette.
//!
//! This module maintains a cache of config file contents so that when errors
//! occur, we can display the relevant source code with span highlighting.

use miette::NamedSource;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};

/// Global registry mapping canonical paths to their source content.
static SOURCES: LazyLock<RwLock<HashMap<PathBuf, Arc<String>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Register a config file's source content for later error reporting.
///
/// The path is canonicalized to ensure consistent lookups regardless of
/// how the path was originally specified. String values and comments are
/// masked before storage (see [`redact_toml_values`]); the stored source is
/// returned so callers building diagnostics from it share the redaction.
pub fn register(path: &Path, content: &str) -> Arc<String> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let redacted = Arc::new(redact_toml_values(content));
    if let Ok(mut sources) = SOURCES.write() {
        sources.insert(canonical, Arc::clone(&redacted));
    }
    redacted
}

/// Mask the contents of TOML string values and comments.
///
/// Config files can hold plaintext secrets (plain provider values, defaults,
/// commented-out credentials), and miette renders the lines around an error
/// span, so source kept for diagnostics must not carry them. Quoted keys stay
/// readable. Every masked byte becomes one `*`, so spans computed against the
/// original text stay valid; line breaks are kept so line numbers match.
pub fn redact_toml_values(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut redacted = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'#' => {
                let end = line_end(bytes, i + 1);
                mask(&mut redacted[i + 1..end]);
                i = end;
            }
            quote @ (b'"' | b'\'') if bytes[i..].starts_with(&[quote; 3]) => {
                let start = i + 3;
                let end = multiline_string_end(bytes, start, quote);
                mask(&mut redacted[start..end]);
                i = (end + 3).min(bytes.len());
            }
            quote @ (b'"' | b'\'') => {
                let start = i + 1;
                let end = string_end(bytes, start, quote);
                let terminated = end < bytes.len() && bytes[end] == quote;
                if !(terminated && is_key_position(bytes, end + 1)) {
                    mask(&mut redacted[start..end]);
                }
                i = if terminated { end + 1 } else { end };
            }
            _ => i += 1,
        }
    }
    String::from_utf8(redacted)
        .expect("redaction only replaces whole UTF-8 sequences with ASCII bytes")
}

fn mask(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().filter(|b| !matches!(b, b'\n' | b'\r')) {
        *byte = b'*';
    }
}

fn line_end(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |offset| from + offset)
}

/// Index of the closing quote of a single-line string, or of the line end
/// when the string is unterminated.
fn string_end(bytes: &[u8], from: usize, quote: u8) -> usize {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => return i,
            b'\\' if quote == b'"' && bytes.get(i + 1).is_some_and(|&b| b != b'\n') => i += 2,
            b if b == quote => return i,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Index of the closing delimiter of a multi-line string, or the end of input.
fn multiline_string_end(bytes: &[u8], from: usize, quote: u8) -> usize {
    let mut i = from;
    while i + 3 <= bytes.len() {
        if quote == b'"' && bytes[i] == b'\\' {
            i += 2;
        } else if bytes[i..].starts_with(&[quote; 3]) {
            return i;
        } else {
            i += 1;
        }
    }
    bytes.len()
}

/// A quoted string is a key when the next token is `=` or a dotted-key `.`.
fn is_key_position(bytes: &[u8], from: usize) -> bool {
    bytes[from..]
        .iter()
        .find(|&&b| b != b' ' && b != b'\t')
        .is_some_and(|&b| b == b'=' || b == b'.')
}

/// Get a NamedSource for the given path, suitable for use with miette errors.
///
/// Returns None if the path was never registered or if the lock cannot be acquired.
/// Returns Arc<NamedSource<...>> to keep the error type size small (Arc is pointer-sized).
pub fn get_named_source(path: &Path) -> Option<Arc<NamedSource<Arc<String>>>> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let sources = SOURCES.read().ok()?;
    sources.get(&canonical).map(|content| {
        Arc::new(NamedSource::new(
            path.display().to_string(),
            Arc::clone(content),
        ))
    })
}

/// Get the raw source content for a path.
///
/// Useful when you need the content without wrapping it in NamedSource.
#[cfg(test)]
pub fn get_content(path: &Path) -> Option<Arc<String>> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let sources = SOURCES.read().ok()?;
    sources.get(&canonical).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_register_and_get() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, "test content").unwrap();
        let path = temp.path();

        register(path, "test content\n");

        let source = get_named_source(path);
        assert!(source.is_some());

        let content = get_content(path);
        assert_eq!(content.as_deref(), Some(&"test content\n".to_string()));
    }

    #[test]
    fn redaction_masks_values_and_comments_but_keeps_structure() {
        let source = concat!(
            "[secrets]\n",
            "A = { provider = \"plain\", value = \"s3cr\\\"t\" } # old: hunter2\n",
            "\"quoted.key\" = 'lit'\n",
            "M = \"\"\"\nline1\nline2\"\"\"\n",
            "U = \"ünïcode\"\n",
            "OPEN = \"unterminated\n",
        );

        let redacted = redact_toml_values(source);

        assert_eq!(redacted.len(), source.len());
        assert_eq!(redacted.lines().count(), source.lines().count());
        for secret in [
            "plain",
            "s3cr",
            "hunter2",
            "lit",
            "line1",
            "line2",
            "ünïcode",
            "unterminated",
        ] {
            assert!(!redacted.contains(secret), "{secret} leaked: {redacted}");
        }
        for structure in [
            "[secrets]",
            "A = { provider = \"",
            "\"quoted.key\" = '",
            "OPEN = \"",
        ] {
            assert!(redacted.contains(structure), "{structure} lost: {redacted}");
        }
    }

    #[test]
    fn test_missing_path() {
        let path = Path::new("/nonexistent/path/to/file.toml");
        assert!(get_named_source(path).is_none());
        assert!(get_content(path).is_none());
    }
}
