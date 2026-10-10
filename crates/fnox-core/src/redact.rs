//! Value-free copies of config and secret input for diagnostics.
//!
//! Config files, import input and parser messages can carry plaintext secrets,
//! and miette renders the lines around an error span. Diagnostics that show
//! such text take a [`Redacted`], which only the masking functions here can
//! produce. Every masked byte becomes one `*` and line breaks are kept, so
//! spans and line numbers computed against the original text stay valid.

use miette::{MietteError, SourceCode, SourceSpan, SpanContents};
use std::sync::Arc;

/// Text with every value masked; constructible only through this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redacted(Arc<String>);

impl Redacted {
    /// Mask TOML values and comments, keeping keys, table headers and punctuation.
    pub fn toml(content: &str) -> Self {
        Self(Arc::new(mask_toml(content)))
    }

    /// Mask everything except whitespace and punctuation, for formats whose
    /// keys cannot be told apart from values without a parser (JSON, YAML).
    pub fn all(content: &str) -> Self {
        let mut bytes = content.as_bytes().to_vec();
        for byte in &mut bytes {
            if !(byte.is_ascii_whitespace() || byte.is_ascii_punctuation()) {
                *byte = b'*';
            }
        }
        Self(Arc::new(into_string(bytes)))
    }

    /// Mask the values a serde or TOML parser message quotes: double-quoted
    /// strings, and backticked scalars after `boolean`, `integer`, `point`,
    /// `character` or `variant`. Field names and expected tokens stay readable.
    pub fn message(message: &str) -> Self {
        Self(Arc::new(mask_message(message)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl SourceCode for Redacted {
    fn read_span<'a>(
        &'a self,
        span: &SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<Box<dyn SpanContents<'a> + 'a>, MietteError> {
        self.0
            .as_str()
            .read_span(span, context_lines_before, context_lines_after)
    }
}

fn into_string(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).expect("masking replaces whole UTF-8 sequences with ASCII bytes")
}

fn mask(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().filter(|b| !matches!(b, b'\n' | b'\r')) {
        *byte = b'*';
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Nesting {
    InlineTable,
    Array,
}

/// Bytes that end a bare TOML token.
fn ends_bare_token(byte: u8) -> bool {
    byte.is_ascii_whitespace() || b"=,{}[]#\"'".contains(&byte)
}

/// Mask TOML values by position: a token is shown only when it sits in key
/// position and is followed by `=`, `.` or a header's `]`. Values, comments,
/// and anything the scanner cannot place are masked.
fn mask_toml(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = bytes.to_vec();
    let mut nesting: Vec<Nesting> = Vec::new();
    let mut expect_key = true;
    let mut in_header = false;
    let mut i = 0;
    while i < bytes.len() {
        let key_position = expect_key || in_header;
        match bytes[i] {
            b' ' | b'\t' | b'\r' => i += 1,
            b'\n' => {
                if nesting.is_empty() {
                    expect_key = true;
                    in_header = false;
                }
                i += 1;
            }
            b'#' => {
                let end = line_end(bytes, i + 1);
                mask(&mut out[i + 1..end]);
                i = end;
            }
            b'[' if nesting.is_empty() && expect_key => {
                in_header = true;
                i += 1;
            }
            b'[' => {
                nesting.push(Nesting::Array);
                expect_key = false;
                i += 1;
            }
            b']' if in_header => {
                if bytes.get(i + 1) != Some(&b']') {
                    in_header = false;
                }
                i += 1;
            }
            b']' => {
                if nesting.last() == Some(&Nesting::Array) {
                    nesting.pop();
                }
                expect_key = false;
                i += 1;
            }
            b'{' => {
                nesting.push(Nesting::InlineTable);
                expect_key = true;
                i += 1;
            }
            b'}' => {
                if nesting.last() == Some(&Nesting::InlineTable) {
                    nesting.pop();
                }
                expect_key = false;
                i += 1;
            }
            b',' => {
                expect_key = nesting.last() == Some(&Nesting::InlineTable);
                i += 1;
            }
            b'=' => {
                expect_key = false;
                i += 1;
            }
            b'.' if key_position => i += 1,
            quote @ (b'"' | b'\'') if bytes[i..].starts_with(&[quote; 3]) => {
                let start = i + 3;
                let end = multiline_string_end(bytes, start, quote);
                mask(&mut out[start..end]);
                i = (end + 3).min(bytes.len());
            }
            quote @ (b'"' | b'\'') => {
                let start = i + 1;
                let end = string_end(bytes, start, quote);
                let terminated = end < bytes.len() && bytes[end] == quote;
                let next = if terminated { end + 1 } else { end };
                if !(terminated && key_position && is_key_end(bytes, next, in_header)) {
                    mask(&mut out[start..end]);
                }
                i = next;
            }
            _ => {
                let start = i;
                let mut end = i;
                while end < bytes.len()
                    && !ends_bare_token(bytes[end])
                    && !(key_position && bytes[end] == b'.')
                {
                    end += 1;
                }
                if !(key_position && is_key_end(bytes, end, in_header)) {
                    mask(&mut out[start..end]);
                }
                i = end;
            }
        }
    }
    into_string(out)
}

/// Whether the next token after a key candidate makes it a key.
fn is_key_end(bytes: &[u8], from: usize, in_header: bool) -> bool {
    bytes[from..]
        .iter()
        .find(|&&b| b != b' ' && b != b'\t')
        .is_some_and(|&b| b == b'=' || b == b'.' || (in_header && b == b']'))
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

/// Words after which serde puts a scalar value in backticks.
const BACKTICKED_VALUE_PREFIXES: [&str; 5] =
    ["boolean", "integer", "point", "character", "variant"];

fn mask_message(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let end = string_end(bytes, i + 1, b'"');
                mask(&mut out[i + 1..end]);
                i = end + 1;
            }
            b'`' => {
                let end = bytes[i + 1..]
                    .iter()
                    .position(|&b| b == b'`')
                    .map_or(bytes.len(), |offset| i + 1 + offset);
                let preceding = message[..i].trim_end();
                if BACKTICKED_VALUE_PREFIXES
                    .iter()
                    .any(|word| preceding.ends_with(word))
                {
                    mask(&mut out[i + 1..end]);
                }
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    into_string(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_hidden(redacted: &Redacted, secrets: &[&str]) {
        for secret in secrets {
            assert!(
                !redacted.as_str().contains(secret),
                "{secret} leaked: {redacted}"
            );
        }
    }

    fn assert_kept(redacted: &Redacted, parts: &[&str]) {
        for part in parts {
            assert!(redacted.as_str().contains(part), "{part} lost: {redacted}");
        }
    }

    #[test]
    fn toml_masks_values_and_comments_but_keeps_structure() {
        let source = concat!(
            "[secrets]\n",
            "A = { provider = \"plain\", value = \"s3cr\\\"t\" } # old: hunter2\n",
            "\"quoted.key\" = 'lit'\n",
            "M = \"\"\"\nline1\nline2\"\"\"\n",
            "U = \"ünïcode\"\n",
            "OPEN = \"unterminated\n",
            "[profiles.dev.secrets]\n",
            "N = 1234\n",
            "L = [\"x1\", { k = \"x2\" }]\n",
        );

        let redacted = Redacted::toml(source);

        assert_eq!(redacted.as_str().len(), source.len());
        assert_eq!(redacted.as_str().lines().count(), source.lines().count());
        assert_hidden(
            &redacted,
            &[
                "plain",
                "s3cr",
                "hunter2",
                "lit",
                "line1",
                "line2",
                "ünïcode",
                "unterminated",
                "1234",
                "x1",
                "x2",
            ],
        );
        assert_kept(
            &redacted,
            &[
                "[secrets]",
                "A = { provider = \"",
                "\"quoted.key\" = '",
                "OPEN = \"",
                "[profiles.dev.secrets]",
                "{ k = \"",
            ],
        );
    }

    #[test]
    fn toml_masks_values_in_malformed_positions() {
        let source = concat!(
            "TOKEN = {provider=\"plain\", value=\"dotted-value\". }\n",
            "BARE = {provider=\"plain\", value=bare-value}\n",
            "\"lone-quoted-value\"\n",
            "lone-bare-value\n",
            "KEY =\n",
            "\"next-line-value\" trailing\n",
        );

        let redacted = Redacted::toml(source);

        assert_hidden(
            &redacted,
            &[
                "dotted-value",
                "bare-value",
                "lone-quoted-value",
                "lone-bare-value",
                "next-line-value",
            ],
        );
        assert_kept(&redacted, &["TOKEN = {provider=", "BARE = {", "KEY ="]);
    }

    #[test]
    fn all_keeps_only_punctuation_and_whitespace() {
        let redacted = Redacted::all("{\"KEY\": \"json-value\",\n key: yaml-value}");

        assert_hidden(&redacted, &["KEY", "json", "yaml", "value"]);
        assert_eq!(
            redacted.as_str(),
            "{\"***\": \"****-*****\",\n ***: ****-*****}"
        );
    }

    #[test]
    fn message_masks_quoted_values_but_keeps_field_names() {
        let redacted = Redacted::message(concat!(
            "invalid type: string \"str-value\", expected a boolean; ",
            "invalid type: integer `1234`, expected a string; ",
            "unknown variant `variant-value`, expected one of `error`, `warn`; ",
            "missing field `provider`",
        ));

        assert_hidden(&redacted, &["str-value", "1234", "variant-value"]);
        assert_kept(
            &redacted,
            &["`error`", "`warn`", "missing field `provider`"],
        );
    }
}
