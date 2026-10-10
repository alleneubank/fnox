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

    /// Mask everything except whitespace, for formats whose keys cannot be
    /// told apart from values without a parser (JSON, YAML). The snippet then
    /// shows only the shape of the input around the error.
    pub fn all(content: &str) -> Self {
        let mut bytes = content.as_bytes().to_vec();
        mask_non_whitespace(&mut bytes);
        Self(Arc::new(into_string(bytes)))
    }

    /// Keep a parser message up to its first quote or backtick and mask the
    /// rest. Parsers quote offending values without escaping them, so nothing
    /// after the first delimiter can be trusted; the masked source snippet
    /// still shows where the error is.
    pub fn message(message: &str) -> Self {
        let mut bytes = message.as_bytes().to_vec();
        if let Some(start) = bytes.iter().position(|b| matches!(b, b'"' | b'`' | b'\'')) {
            mask_non_whitespace(&mut bytes[start..]);
        }
        Self(Arc::new(into_string(bytes)))
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

fn mask_non_whitespace(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().filter(|b| !b.is_ascii_whitespace()) {
        *byte = b'*';
    }
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
    // An `=` whose value has not started yet; the value may follow on a later
    // line in malformed input, so a newline must not turn it into a key.
    let mut value_pending = false;
    let mut i = 0;
    while i < bytes.len() {
        let key_position = expect_key || in_header;
        if value_pending && !matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b'#') {
            value_pending = false;
            if bytes[i] == b'[' {
                nesting.push(Nesting::Array);
                i += 1;
                continue;
            }
        }
        match bytes[i] {
            b' ' | b'\t' | b'\r' => i += 1,
            b'\n' => {
                if nesting.is_empty() && !value_pending {
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
                value_pending = !in_header && nesting.last() != Some(&Nesting::Array);
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
                let is_bare_key = bytes[start..end].iter().all(|&b| is_bare_key_byte(b));
                if !(key_position && is_bare_key && is_key_end(bytes, end, in_header)) {
                    mask(&mut out[start..end]);
                }
                i = end;
            }
        }
    }
    into_string(out)
}

/// Whether a key candidate ending at `from` is followed, on the same line, by
/// more dotted key parts and then `=` (or a header's `]`). Anything else,
/// including a value continued onto a new line, leaves the candidate masked.
fn is_key_end(bytes: &[u8], from: usize, in_header: bool) -> bool {
    let mut i = skip_blanks(bytes, from);
    loop {
        match bytes.get(i) {
            Some(b'=') => return !in_header,
            Some(b']') => return in_header,
            Some(b'.') => i = skip_blanks(bytes, i + 1),
            _ => return false,
        }
        i = match bytes.get(i) {
            Some(&quote @ (b'"' | b'\'')) => {
                let end = string_end(bytes, i + 1, quote);
                if bytes.get(end) != Some(&quote) {
                    return false;
                }
                skip_blanks(bytes, end + 1)
            }
            Some(&b) if is_bare_key_byte(b) => {
                let len = bytes[i..]
                    .iter()
                    .take_while(|&&b| is_bare_key_byte(b))
                    .count();
                skip_blanks(bytes, i + len)
            }
            _ => return false,
        };
    }
}

fn is_bare_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn skip_blanks(bytes: &[u8], from: usize) -> usize {
    from + bytes[from.min(bytes.len())..]
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count()
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
    fn toml_masks_values_continued_onto_a_new_line() {
        let redacted =
            Redacted::toml("TOKEN =\n\"next-line-value\".oops\nBARE =\nbare-value.more\n");

        assert_hidden(
            &redacted,
            &["next-line-value", "oops", "bare-value", "more"],
        );
        assert_kept(&redacted, &["TOKEN =", "BARE ="]);
    }

    #[test]
    fn toml_masks_arrays_and_dotted_pairs_continued_onto_a_new_line() {
        let redacted = Redacted::toml(
            "TOKEN =\n[\"array-value\"]\nOTHER =\n\"dotted-value\".oops = 1\nNEXT = 1\n",
        );

        assert_hidden(&redacted, &["array-value", "dotted-value", "oops"]);
        assert_kept(&redacted, &["TOKEN =", "OTHER =", "NEXT = "]);
    }

    #[test]
    fn all_keeps_only_whitespace() {
        let redacted = Redacted::all("{\"KEY\": \"!@#$%^&*()_+-=\",\n key: yaml-value}");

        assert_eq!(
            redacted.as_str(),
            "******* *****************\n **** ***********"
        );
    }

    #[test]
    fn message_keeps_only_the_text_before_the_first_quote() {
        for message in [
            "invalid type: string \"str-value\", expected a boolean",
            "invalid type: integer `1234`, expected a string",
            "unknown variant `x`backtick-value`, expected one of `error`, `warn`",
            "invalid value: 'single-value'",
        ] {
            let redacted = Redacted::message(message);
            for secret in ["str-value", "1234", "backtick-value", "single-value"] {
                assert!(
                    !redacted.as_str().contains(secret),
                    "{secret} leaked: {redacted}"
                );
            }
        }
        assert_eq!(
            Redacted::message("unknown variant `v`, expected `a`").as_str(),
            "unknown variant **** ******** ***"
        );
    }
}
