//! The pull request under review: its event, its earlier review comments and the review this
//! run posts, all through the GitHub REST API in process with the job's token.

use serde_json::Value;

use crate::github_api::{github_message, Client, Method, Reply};

const PER_PAGE: usize = 30;
const PAGES_MAX: usize = 10;
const BODY_EXCERPT_CHARS: usize = 300;

/// The fields of a `pull_request` event the review reads.
#[derive(Debug, PartialEq, Eq)]
pub struct PullRequest {
    pub number: u64,
    pub base: String,
    pub head: String,
    pub head_repository: String,
}

/// One finding an earlier review posted: its fingerprint and what the find pass is told
/// about it.
#[derive(Debug, PartialEq, Eq)]
pub struct Posted {
    pub fingerprint: String,
    pub excerpt: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PostOutcome {
    Posted { url: String },
    Failed(u16, Option<String>),
    Unrecognised(&'static str),
}

pub fn commit_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Decodes the event file Actions writes for a `pull_request` run.
pub fn decode_event(text: &str) -> Result<PullRequest, String> {
    let event: Value =
        serde_json::from_str(text).map_err(|_| "the event file is not JSON".to_string())?;
    let pull_request = event
        .get("pull_request")
        .ok_or("the event is not a pull_request event")?;
    let text_at = |pointer: &str| pull_request.pointer(pointer).and_then(Value::as_str);
    let number = pull_request
        .get("number")
        .and_then(Value::as_u64)
        .filter(|number| *number > 0)
        .ok_or("the event has no pull request number")?;
    let (Some(base), Some(head)) = (text_at("/base/sha"), text_at("/head/sha")) else {
        return Err("the event has no base or head commit".to_string());
    };
    if !commit_sha(base) || !commit_sha(head) {
        return Err("the event's base or head is not a commit id".to_string());
    }
    let head_repository = text_at("/head/repo/full_name")
        .ok_or("the event has no head repository")?
        .to_string();
    Ok(PullRequest {
        number,
        base: base.to_string(),
        head: head.to_string(),
        head_repository,
    })
}

fn excerpt(prefix: &str, text: &str) -> String {
    let text = text.trim();
    let skipped = text.chars().count().saturating_sub(BODY_EXCERPT_CHARS);
    format!("{prefix}{}", text.chars().skip(skipped).collect::<String>())
}

/// Our findings in one inline comment, located by its path and line.
fn from_comment(comment: &Value) -> Vec<Posted> {
    let body = comment
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path = comment
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let line = comment
        .get("line")
        .and_then(Value::as_u64)
        .map_or_else(String::new, |line| format!(":{line}"));
    super::findings::marked_entries(body)
        .into_iter()
        .map(|(fingerprint, text)| Posted {
            fingerprint: fingerprint.to_string(),
            excerpt: excerpt(&format!("{path}{line}: "), text),
        })
        .collect()
}

/// Our findings in one review's body, each located by its own entry.
fn from_review(review: &Value) -> Vec<Posted> {
    let body = review
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default();
    super::findings::marked_entries(body)
        .into_iter()
        .map(|(fingerprint, text)| Posted {
            fingerprint: fingerprint.to_string(),
            excerpt: excerpt("", text),
        })
        .collect()
}

/// Every item of a paged listing, decoded; a listing that would go past [`PAGES_MAX`] is an
/// error, not a truncation.
fn listing(
    client: &Client,
    token: &str,
    path: &str,
    decode: fn(&Value) -> Vec<Posted>,
) -> Result<Vec<Posted>, String> {
    let mut posted = Vec::new();
    for page in 1..=PAGES_MAX {
        let paged = format!("{path}?per_page={PER_PAGE}&page={page}");
        let body = match client.request(Method::Get, &paged, token, None) {
            Reply::Response { status: 200, body } => body,
            Reply::Response { status, body } => {
                return Err(format!(
                    "listing {path} ended HTTP {status}{}",
                    github_message(&body)
                        .map(|m| format!(", {m}"))
                        .unwrap_or_default()
                ))
            }
            Reply::BodyTooLarge => return Err(format!("a page of {path} is over its cap")),
            Reply::Failed(reason) => return Err(format!("listing {path}: {reason}")),
        };
        let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&body) else {
            return Err(format!("a page of {path} is not a JSON array"));
        };
        posted.extend(items.iter().flat_map(decode));
        if items.len() < PER_PAGE {
            return Ok(posted);
        }
    }
    Err(format!(
        "{path} lists more than {} items; the review reads at most that many",
        PER_PAGE.saturating_mul(PAGES_MAX)
    ))
}

/// The findings earlier reviews posted on the pull request, inline and in review bodies.
pub fn posted_findings(
    client: &Client,
    token: &str,
    repository: &str,
    number: u64,
) -> Result<Vec<Posted>, String> {
    let base = format!("/repos/{repository}/pulls/{number}");
    let mut posted = listing(client, token, &format!("{base}/comments"), from_comment)?;
    posted.extend(listing(
        client,
        token,
        &format!("{base}/reviews"),
        from_review,
    )?);
    Ok(posted)
}

pub fn decode_post(status: u16, body: &str) -> PostOutcome {
    if status != 200 {
        return PostOutcome::Failed(status, github_message(body));
    }
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return PostOutcome::Unrecognised("the review response is not JSON");
    };
    value
        .get("html_url")
        .and_then(Value::as_str)
        .filter(|url| url.starts_with("https://"))
        .map_or(
            PostOutcome::Unrecognised("the review response has no html_url"),
            |url| PostOutcome::Posted {
                url: url.to_string(),
            },
        )
}

/// Posts one review that comments and never approves or requests changes.
pub fn post_review(
    client: &Client,
    token: &str,
    repository: &str,
    pull_request: &PullRequest,
    body: &str,
    comments: &[(String, u32, String)],
) -> PostOutcome {
    let comments: Vec<Value> = comments
        .iter()
        .map(|(path, line, text)| {
            serde_json::json!({"path": path, "line": line, "side": "RIGHT", "body": text})
        })
        .collect();
    let request = serde_json::json!({
        "commit_id": pull_request.head,
        "event": "COMMENT",
        "body": body,
        "comments": comments,
    })
    .to_string();
    let path = format!("/repos/{repository}/pulls/{}/reviews", pull_request.number);
    match client.request(Method::Post, &path, token, Some(&request)) {
        Reply::Response { status, body } => decode_post(status, &body),
        Reply::BodyTooLarge => PostOutcome::Unrecognised("the review response is over its cap"),
        Reply::Failed(reason) => PostOutcome::Unrecognised(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_api::tests::listener;

    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
    const BASE: &str = "89abcdef0123456789abcdef0123456789abcdef";

    fn event(head: &str) -> String {
        serde_json::json!({"pull_request": {
            "number": 12,
            "base": {"sha": BASE},
            "head": {"sha": head, "repo": {"full_name": "o/r"}},
        }})
        .to_string()
    }

    #[test]
    fn the_event_decodes_and_a_malformed_one_is_refused() {
        assert_eq!(
            decode_event(&event(HEAD)),
            Ok(PullRequest {
                number: 12,
                base: BASE.to_string(),
                head: HEAD.to_string(),
                head_repository: "o/r".to_string(),
            })
        );
        assert!(decode_event(&event("main")).is_err());
        assert!(decode_event(&event(&HEAD.to_uppercase())).is_err());
        assert!(decode_event(r#"{"push": {}}"#).is_err());
        assert!(decode_event("nope").is_err());
    }

    fn comment(body: &str) -> Value {
        serde_json::json!({"body": body, "path": "a.rs", "line": 3})
    }

    #[test]
    fn our_marked_findings_are_collected_from_comments_and_review_bodies() {
        let ours = "x\n<!-- tycho-review 0123456789abcdef -->";
        let full: Vec<Value> = (0..PER_PAGE).map(|_| comment("someone else")).collect();
        let last = vec![comment(ours), comment("<!-- tycho-review nothex -->")];
        let review = serde_json::json!({"body":
            "- `b.rs:9` (Low, correctness): s\n  f\n  <!-- tycho-review fedcba9876543210 -->"});
        let (base, seen) = listener(vec![
            (200, Value::Array(full).to_string()),
            (200, Value::Array(last).to_string()),
            (
                200,
                Value::Array(vec![review, serde_json::json!({"body": null})]).to_string(),
            ),
        ]);
        let posted = posted_findings(&Client::loopback(&base), "t", "o/r", 12).unwrap();
        let fingerprints: Vec<&str> = posted
            .iter()
            .map(|entry| entry.fingerprint.as_str())
            .collect();
        assert_eq!(fingerprints, ["0123456789abcdef", "fedcba9876543210"]);
        assert_eq!(posted.first().unwrap().excerpt, "a.rs:3: x");
        assert!(posted.get(1).unwrap().excerpt.contains("b.rs:9"));
        let requests = seen.recv().unwrap();
        assert!(requests
            .get(1)
            .unwrap()
            .starts_with("GET /repos/o/r/pulls/12/comments?per_page=30&page=2 "));
        assert!(requests
            .get(2)
            .unwrap()
            .starts_with("GET /repos/o/r/pulls/12/reviews?per_page=30&page=1 "));
    }

    #[test]
    fn a_listing_past_its_bound_or_a_refusal_is_an_error() {
        let full = Value::Array((0..PER_PAGE).map(|_| comment("c")).collect());
        let (base, _seen) = listener(vec![(200, full.to_string()); PAGES_MAX]);
        let error = posted_findings(&Client::loopback(&base), "t", "o/r", 1).unwrap_err();
        assert!(error.contains("more than 300"), "{error}");
        let (base, _seen) = listener(vec![(
            403,
            r#"{"message":"Resource not accessible"}"#.into(),
        )]);
        let error = posted_findings(&Client::loopback(&base), "t", "o/r", 1).unwrap_err();
        assert!(
            error.contains("HTTP 403, Resource not accessible"),
            "{error}"
        );
    }

    #[test]
    fn the_review_comments_on_the_head_commit_and_never_approves() {
        let (base, seen) = listener(vec![(
            200,
            r#"{"id":1,"html_url":"https://github.com/o/r/pull/12#pullrequestreview-1"}"#.into(),
        )]);
        let pull_request = decode_event(&event(HEAD)).unwrap();
        let outcome = post_review(
            &Client::loopback(&base),
            "t",
            "o/r",
            &pull_request,
            "body",
            &[("a.rs".to_string(), 4, "text".to_string())],
        );
        assert!(matches!(outcome, PostOutcome::Posted { .. }), "{outcome:?}");
        let requests = seen.recv().unwrap();
        let raw = requests.first().unwrap();
        assert!(raw.starts_with("POST /repos/o/r/pulls/12/reviews HTTP/1.1\r\n"));
        let sent: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(
            sent,
            serde_json::json!({"commit_id": HEAD, "event": "COMMENT", "body": "body",
                "comments": [{"path": "a.rs", "line": 4, "side": "RIGHT", "body": "text"}]})
        );
    }

    #[test]
    fn post_decoder_covers_each_state() {
        assert_eq!(
            decode_post(422, r#"{"message":"Unprocessable Entity"}"#),
            PostOutcome::Failed(422, Some("Unprocessable Entity".to_string()))
        );
        assert!(matches!(
            decode_post(200, "x"),
            PostOutcome::Unrecognised(_)
        ));
        assert!(matches!(
            decode_post(200, r#"{"html_url":"javascript:x"}"#),
            PostOutcome::Unrecognised(_)
        ));
    }
}
