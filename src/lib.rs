//! Mask credentials in database connection strings.
//!
//! `redactdsn` replaces the password in URLs such as
//! `postgres://app:s3cret@db:5432/app` with `***`, and masks query
//! parameters that commonly carry secrets (`password`, `token`, `key`,
//! `secret`, `sslpassword`). Everything else is kept, so the redacted
//! string is still useful when debugging which host or database an app
//! is connecting to.
//!
//! ```
//! assert_eq!(
//!     redactdsn::redact("postgres://app:s3cret@db:5432/app?sslmode=require"),
//!     "postgres://app:***@db:5432/app?sslmode=require"
//! );
//! assert_eq!(
//!     redactdsn::redact("redis://:hunter2@cache:6379/0"),
//!     "redis://:***@cache:6379/0"
//! );
//! assert_eq!(
//!     redactdsn::redact("mysql://u@h/db?password=x&charset=utf8"),
//!     "mysql://u@h/db?password=***&charset=utf8"
//! );
//! ```
//!
//! [`redact_text`] scans free text, such as a log line or an error message,
//! and redacts every URL it finds.
//!
//! Connection strings for managed or self-hosted databases end up in logs
//! more often than anyone wants. See how Peon handles
//! [self-hosted databases](https://peon.sh/solutions/databases) with
//! credentials kept out of application code. Built by a contributor to
//! [Peon](https://peon.sh/), an open-source self-hosted deployment platform.

const MASK: &str = "***";
const SECRET_PARAMS: &[&str] = &["password", "pass", "pwd", "token", "secret", "key", "sslpassword", "apikey", "api_key", "access_token"];

/// Redact a single connection string. Strings without a scheme are returned unchanged.
pub fn redact(dsn: &str) -> String {
    let Some(scheme_end) = dsn.find("://") else { return dsn.to_string() };
    let (scheme, rest) = dsn.split_at(scheme_end + 3);
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    let authority = match authority.rfind('@') {
        Some(at) => {
            let (userinfo, host) = authority.split_at(at);
            match userinfo.find(':') {
                Some(c) => format!("{}:{}{}", &userinfo[..c], MASK, host),
                None => authority.to_string(),
            }
        }
        None => authority.to_string(),
    };
    format!("{}{}{}", scheme, authority, redact_query(tail))
}

fn redact_query(tail: &str) -> String {
    let Some(q) = tail.find('?') else { return tail.to_string() };
    let (path, query) = tail.split_at(q + 1);
    let (query, frag) = match query.find('#') {
        Some(h) => query.split_at(h),
        None => (query, ""),
    };
    let parts: Vec<String> = query
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, _)) if SECRET_PARAMS.contains(&k.to_ascii_lowercase().as_str()) => format!("{}={}", k, MASK),
            _ => kv.to_string(),
        })
        .collect();
    format!("{}{}{}", path, parts.join("&"), frag)
}

/// Redact every `scheme://` URL found in free text, leaving the rest untouched.
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, word) in text.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if word.contains("://") {
            let start = word.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(0);
            let end = word.rfind(|c: char| !matches!(c, '"' | '\'' | ')' | ',' | ';')).map(|e| e + 1).unwrap_or(word.len());
            if start < end {
                out.push_str(&word[..start]);
                out.push_str(&redact(&word[start..end]));
                out.push_str(&word[end..]);
                continue;
            }
        }
        out.push_str(word);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_strings_without_password() {
        assert_eq!(redact("postgres://app@db/app"), "postgres://app@db/app");
        assert_eq!(redact("not a url"), "not a url");
    }

    #[test]
    fn password_with_at_sign_in_userinfo() {
        assert_eq!(redact("postgres://u:p@ss@db/app"), "postgres://u:***@db/app");
    }

    #[test]
    fn fragment_and_case_insensitive_params() {
        assert_eq!(redact("amqp://h/v?Token=abc#x"), "amqp://h/v?Token=***#x");
    }

    #[test]
    fn text_scan() {
        let line = "connect failed url=\"postgres://a:b@db:5432/x\", retrying";
        assert_eq!(redact_text(line), "connect failed url=\"postgres://a:***@db:5432/x\", retrying");
    }
}
