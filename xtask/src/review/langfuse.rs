//! One Langfuse trace per review, sent as OTLP/JSON to Langfuse's OpenTelemetry endpoint in
//! process: a root span for the review and a generation span for each Claude pass. The keys
//! never reach the Claude CLI's environment.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde_json::{json, Value};

use super::claude_run::Usage;
use crate::config::sha256_line;
use crate::github_api::{Credential, Method, PlainClient, Reply};

pub const BASE_URL_VARIABLE: &str = "LANGFUSE_BASE_URL";
pub const PUBLIC_KEY_VARIABLE: &str = "LANGFUSE_PUBLIC_KEY";
pub const SECRET_KEY_VARIABLE: &str = "LANGFUSE_SECRET_KEY";
const TRACES_PATH: &str = "/api/public/otel/v1/traces";
const INGESTION_VERSION: (&str, &str) = ("x-langfuse-ingestion-version", "4");
const KEY_MAX_CHARS: usize = 256;
const BASE_URL_MAX_CHARS: usize = 512;
const SERVICE_NAME: &str = "tycho-review";
const TRACE_ID_HEX_CHARS: usize = 32;
const SPAN_ID_HEX_CHARS: usize = 16;

/// Where traces go and the Basic credential they carry.
pub struct Langfuse {
    endpoint: String,
    basic: String,
}

impl std::fmt::Debug for Langfuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Langfuse")
            .field("endpoint", &self.endpoint)
            .field("basic", &"[redacted]")
            .finish()
    }
}

/// One Claude pass: a generation in the trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    pub name: String,
    pub model: &'static str,
    pub started: SystemTime,
    pub ended: SystemTime,
    pub input: String,
    pub output: String,
    pub outcome: String,
    pub usage: Usage,
}

/// The review as Langfuse shows it: grouped into a session per pull request, tagged with
/// the mode, with the verdict and counts as metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    pub name: String,
    pub session: String,
    pub tags: Vec<String>,
    pub started: SystemTime,
    pub ended: SystemTime,
    pub input: String,
    pub output: String,
    pub metadata: Vec<(String, String)>,
    pub generations: Vec<Generation>,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn usable_key(name: &str, value: &str) -> Result<(), String> {
    if value.len() <= KEY_MAX_CHARS && value.chars().all(|c| c.is_ascii_graphic()) {
        Ok(())
    } else {
        Err(format!("{name} is not a Langfuse key"))
    }
}

/// The Langfuse settings: all three set traces, none set turns tracing off, and anything
/// between is an error naming what is missing.
pub fn read(
    base_url: Option<String>,
    public_key: Option<String>,
    secret_key: Option<String>,
) -> Result<Option<Langfuse>, String> {
    match (
        non_empty(base_url),
        non_empty(public_key),
        non_empty(secret_key),
    ) {
        (None, None, None) => Ok(None),
        (Some(base_url), Some(public_key), Some(secret_key)) => {
            let base_url = base_url.trim_end_matches('/');
            let url_valid = base_url.starts_with("https://")
                && base_url.len() <= BASE_URL_MAX_CHARS
                && base_url.chars().all(|c| c.is_ascii_graphic())
                && !base_url.contains(['?', '#']);
            if !url_valid {
                return Err(format!("{BASE_URL_VARIABLE} is not an HTTPS base URL"));
            }
            usable_key(PUBLIC_KEY_VARIABLE, &public_key)?;
            usable_key(SECRET_KEY_VARIABLE, &secret_key)?;
            Ok(Some(Langfuse {
                endpoint: format!("{base_url}{TRACES_PATH}"),
                basic: base64::engine::general_purpose::STANDARD
                    .encode(format!("{public_key}:{secret_key}")),
            }))
        }
        _ => Err(format!(
            "{BASE_URL_VARIABLE}, {PUBLIC_KEY_VARIABLE} and {SECRET_KEY_VARIABLE} are set \
             together or not at all"
        )),
    }
}

fn hex_id(seed: &str, index: usize, chars: usize) -> String {
    String::from_utf8_lossy(&sha256_line(format!("{seed}/{index}").as_bytes()))
        .chars()
        .take(chars)
        .collect()
}

/// Nanoseconds since the epoch as a decimal string, the OTLP/JSON form of a 64-bit integer.
fn nanos(time: SystemTime) -> String {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos())
        .to_string()
}

fn text(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

/// The trace-level attributes Langfuse wants on every span, so filters work per observation.
fn trace_attributes(trace: &Trace) -> Vec<Value> {
    let tags: Vec<Value> = trace
        .tags
        .iter()
        .map(|tag| json!({"stringValue": tag}))
        .collect();
    let mut attributes = vec![
        text("langfuse.trace.name", &trace.name),
        text("langfuse.session.id", &trace.session),
        json!({"key": "langfuse.trace.tags", "value": {"arrayValue": {"values": tags}}}),
    ];
    attributes.extend(
        trace
            .metadata
            .iter()
            .map(|(key, value)| text(&format!("langfuse.trace.metadata.{key}"), value)),
    );
    attributes
}

fn generation_span(trace: &Trace, generation: &Generation, ids: (&str, &str, String)) -> Value {
    let (trace_id, root_id, span_id) = ids;
    let mut attributes = trace_attributes(trace);
    attributes.extend([
        text("langfuse.observation.type", "generation"),
        text("langfuse.observation.model.name", generation.model),
        text("langfuse.observation.input", &generation.input),
        text("langfuse.observation.output", &generation.output),
        text("langfuse.observation.metadata.outcome", &generation.outcome),
        text(
            "langfuse.observation.usage_details",
            &json!({"input": generation.usage.input_tokens,
                    "output": generation.usage.output_tokens})
            .to_string(),
        ),
        text(
            "langfuse.observation.cost_details",
            &json!({"total": dollars(generation.usage.cost)}).to_string(),
        ),
    ]);
    json!({
        "traceId": trace_id,
        "spanId": span_id,
        "parentSpanId": root_id,
        "name": generation.name,
        "kind": 1,
        "startTimeUnixNano": nanos(generation.started),
        "endTimeUnixNano": nanos(generation.ended),
        "attributes": attributes,
    })
}

#[allow(
    clippy::cast_precision_loss,
    reason = "micro-dollars below 2^53 convert exactly; the bound is a million dollars"
)]
fn dollars(micro_dollars: u64) -> f64 {
    micro_dollars as f64 / 1e6
}

/// The OTLP/JSON request body; `seed` makes the trace and span ids.
pub fn body(trace: &Trace, seed: &str) -> Value {
    let trace_id = hex_id(seed, 0, TRACE_ID_HEX_CHARS);
    let root_id = hex_id(seed, 0, SPAN_ID_HEX_CHARS);
    let mut root_attributes = trace_attributes(trace);
    root_attributes.extend([
        text("langfuse.observation.input", &trace.input),
        text("langfuse.observation.output", &trace.output),
    ]);
    let mut spans = vec![json!({
        "traceId": trace_id,
        "spanId": root_id,
        "name": trace.name,
        "kind": 1,
        "startTimeUnixNano": nanos(trace.started),
        "endTimeUnixNano": nanos(trace.ended),
        "attributes": root_attributes,
    })];
    spans.extend(
        trace
            .generations
            .iter()
            .enumerate()
            .map(|(index, generation)| {
                let span_id = hex_id(seed, index.saturating_add(1), SPAN_ID_HEX_CHARS);
                generation_span(trace, generation, (&trace_id, &root_id, span_id))
            }),
    );
    json!({"resourceSpans": [{
        "resource": {"attributes": [text("service.name", SERVICE_NAME)]},
        "scopeSpans": [{"scope": {"name": SERVICE_NAME}, "spans": spans}],
    }]})
}

/// A seed no two runs share: the process id and the clock.
pub fn seed() -> String {
    format!("{}-{}", std::process::id(), nanos(SystemTime::now()))
}

/// Langfuse answers 2xx; a body that reports rejected spans is a failure too.
fn decode_export(status: u16, body: &str) -> Result<(), String> {
    if !(200..300).contains(&status) {
        return Err(format!("Langfuse refused the trace with HTTP {status}"));
    }
    let rejected = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| value.pointer("/partialSuccess/rejectedSpans")?.as_u64())
        .unwrap_or(0);
    if rejected > 0 {
        return Err(format!("Langfuse rejected {rejected} spans of the trace"));
    }
    Ok(())
}

pub fn export(langfuse: &Langfuse, trace: &Trace) -> Result<(), String> {
    export_with(&PlainClient::https(), langfuse, trace, &seed())
}

fn export_with(
    client: &PlainClient,
    langfuse: &Langfuse,
    trace: &Trace,
    seed: &str,
) -> Result<(), String> {
    let reply = client.request_with(
        Method::Post,
        &langfuse.endpoint,
        Credential::Basic(&langfuse.basic),
        &[INGESTION_VERSION],
        Some(&body(trace, seed).to_string()),
    );
    match reply {
        Reply::Response { status, body } => decode_export(status, &body),
        Reply::BodyTooLarge => Err("the Langfuse response is over its cap".to_string()),
        Reply::Failed(reason) => Err(format!("sending the trace to Langfuse: {reason}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_api::tests::listener;
    use std::time::Duration;

    fn trace() -> Trace {
        let started = UNIX_EPOCH
            .checked_add(Duration::from_secs(1_800_000_000))
            .unwrap();
        Trace {
            name: "code-review".to_string(),
            session: "o/r#12".to_string(),
            tags: vec!["post".to_string()],
            started,
            ended: started.checked_add(Duration::from_secs(90)).unwrap(),
            input: "diff".to_string(),
            output: "approve".to_string(),
            metadata: vec![("verdict".to_string(), "approve".to_string())],
            generations: vec![Generation {
                name: "find".to_string(),
                model: "opus",
                started,
                ended: started.checked_add(Duration::from_secs(60)).unwrap(),
                input: "instructions".to_string(),
                output: r#"{"findings":[]}"#.to_string(),
                outcome: "answered".to_string(),
                usage: Usage {
                    input_tokens: 1000,
                    output_tokens: 200,
                    cost: 1_500_000,
                },
            }],
        }
    }

    fn attribute<'a>(span: &'a Value, key: &str) -> Option<&'a Value> {
        span.get("attributes")?
            .as_array()?
            .iter()
            .find(|attribute| attribute.get("key").and_then(Value::as_str) == Some(key))?
            .get("value")
    }

    #[test]
    fn the_secret_key_is_taken_out_of_the_environment_at_startup() {
        assert!(crate::secrets::SECRET_VARIABLES.contains(&SECRET_KEY_VARIABLE));
    }

    #[test]
    fn all_three_settings_trace_none_turns_tracing_off_and_some_is_an_error() {
        assert!(read(None, None, None).unwrap().is_none());
        let langfuse = read(
            Some("https://us.cloud.langfuse.com/".into()),
            Some("pk-lf-1".into()),
            Some("sk-lf-2".into()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            langfuse.endpoint,
            "https://us.cloud.langfuse.com/api/public/otel/v1/traces"
        );
        assert!(!format!("{langfuse:?}").contains("sk-lf-2"));
        let partial = read(Some("https://x".into()), None, Some("sk".into())).unwrap_err();
        assert!(partial.contains(PUBLIC_KEY_VARIABLE), "{partial}");
        assert!(read(Some("http://x".into()), Some("p".into()), Some("s".into())).is_err());
    }

    #[test]
    fn the_body_is_otlp_json_with_string_times_and_langfuse_attributes_on_every_span() {
        let body = body(&trace(), "seed");
        let spans = body
            .pointer("/resourceSpans/0/scopeSpans/0/spans")
            .and_then(Value::as_array)
            .unwrap();
        let [root, find] = spans.as_slice() else {
            panic!("{spans:?}");
        };
        let trace_id = root.get("traceId").and_then(Value::as_str).unwrap();
        assert_eq!(trace_id.len(), 32);
        assert_eq!(find.get("traceId").and_then(Value::as_str), Some(trace_id));
        assert_eq!(find.get("parentSpanId"), root.get("spanId"));
        assert_eq!(
            root.get("startTimeUnixNano"),
            Some(&json!("1800000000000000000"))
        );
        for span in [root, find] {
            assert_eq!(
                attribute(span, "langfuse.session.id"),
                Some(&json!({"stringValue": "o/r#12"}))
            );
            assert_eq!(
                attribute(span, "langfuse.trace.tags"),
                Some(&json!({"arrayValue": {"values": [{"stringValue": "post"}]}}))
            );
        }
        assert_eq!(
            attribute(find, "langfuse.observation.type"),
            Some(&json!({"stringValue": "generation"}))
        );
        assert_eq!(
            attribute(find, "langfuse.observation.usage_details"),
            Some(&json!({"stringValue": r#"{"input":1000,"output":200}"#}))
        );
        assert_eq!(
            attribute(find, "langfuse.observation.cost_details"),
            Some(&json!({"stringValue": r#"{"total":1.5}"#}))
        );
    }

    #[test]
    fn export_posts_with_basic_auth_and_the_ingestion_version() {
        let (base, seen) = listener(vec![
            (200, "{}".to_string()),
            (200, r#"{"partialSuccess":{"rejectedSpans":1}}"#.to_string()),
            (401, "{}".to_string()),
        ]);
        let langfuse = Langfuse {
            endpoint: format!("{base}{TRACES_PATH}"),
            basic: "cGs6c2s=".to_string(),
        };
        let client = PlainClient::loopback();
        assert_eq!(export_with(&client, &langfuse, &trace(), "s"), Ok(()));
        assert!(export_with(&client, &langfuse, &trace(), "s")
            .unwrap_err()
            .contains("rejected 1 spans"));
        assert!(export_with(&client, &langfuse, &trace(), "s")
            .unwrap_err()
            .contains("HTTP 401"));
        let requests = seen.recv().unwrap();
        let raw = requests.first().unwrap();
        let lower = raw.to_ascii_lowercase();
        assert!(
            raw.starts_with("POST /api/public/otel/v1/traces HTTP/1.1\r\n"),
            "{raw}"
        );
        assert!(lower.contains("\r\nauthorization: basic cgs6c2s=\r\n"));
        assert!(lower.contains("\r\nx-langfuse-ingestion-version: 4\r\n"));
        assert!(lower.contains("\r\ncontent-type: application/json\r\n"));
    }
}
