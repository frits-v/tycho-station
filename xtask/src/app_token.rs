//! GitHub App installation tokens for the release pull request.
//!
//! The App's private key signs a short JWT; `gh api` trades it for an installation token
//! scoped to one repository and two permissions. Credentials travel only through child
//! process environments (`GH_TOKEN`), never through arguments, output or error text.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};

use crate::process::{run_bounded, Exit};

pub const CLIENT_ID_VARIABLE: &str = "TYCHO_RELEASE_CLIENT_ID";
pub const APP_ID_VARIABLE: &str = "TYCHO_RELEASE_APP_ID";
pub const APP_KEY_VARIABLE: &str = "TYCHO_RELEASE_APP_PRIVATE_KEY";
const REPOSITORY_VARIABLE: &str = "GITHUB_REPOSITORY";
const APP_ID_MAX_DIGITS: usize = 20;
/// GitHub App client ids are `Iv` and a short alphanumeric suffix, about twenty characters.
const CLIENT_ID_MAX_CHARS: usize = 64;
const PRIVATE_KEY_MAX_BYTES: usize = 16 * 1024;
const REPOSITORY_MAX_CHARS: usize = 140;
const TOKEN_MAX_CHARS: usize = 1024;
/// GitHub rejects an `iat` ahead of its clock; backdating absorbs runner clock drift.
const JWT_BACKDATE_SECONDS: u64 = 60;
/// GitHub refuses an `exp` more than ten minutes ahead; with the backdate, `exp` lands nine
/// minutes ahead of now.
pub const JWT_MAX_LIFETIME_SECONDS: u64 = 600;
const GH_TIMEOUT: Duration = Duration::from_secs(60);
/// The grant requested for the token; GitHub adds `metadata: read` to every installation token.
const REQUESTED_PERMISSIONS: [(&str, &str); 2] =
    [("contents", "write"), ("pull_requests", "write")];
const IMPLICIT_PERMISSION: (&str, &str) = ("metadata", "read");
static CONFIG_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const GH_INHERITED_VARIABLES: [&str; 4] = ["PATH", "TMPDIR", "LANG", "LC_ALL"];

/// The App's identity and signing key, read from the environment. `issuer` is the JWT `iss`:
/// the App's client id, or its numeric App id when no client id is set.
pub struct AppCredentials {
    issuer: String,
    key: EncodingKey,
}

impl fmt::Debug for AppCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppCredentials")
            .field("issuer", &self.issuer)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// An installation token; its value leaves this module only through [`InstallationToken::expose`].
#[derive(PartialEq, Eq)]
pub struct InstallationToken(String);

impl InstallationToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InstallationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallationToken([redacted])")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Repository {
    owner: String,
    name: String,
}

#[derive(Debug, PartialEq, Eq)]
enum InstallationOutcome {
    Found(u64),
    Failed(Exit),
    Unrecognised(&'static str),
}

/// `Unrecognised` carries a fixed reason, never response text: a malformed success body may
/// hold the token. A token GitHub issued but the xtask refuses travels in its variant so it can
/// be revoked.
#[derive(Debug, PartialEq, Eq)]
enum TokenOutcome {
    Issued(InstallationToken),
    Failed(Exit),
    Overgranted(InstallationToken),
    UnreadableGrant(InstallationToken),
    Unrecognised(&'static str),
}

fn missing_credentials() -> String {
    format!(
        "{CLIENT_ID_VARIABLE} (variable, preferred) or {APP_ID_VARIABLE} (variable, accepted), \
         and {APP_KEY_VARIABLE} (secret), of the `release` environment must be set: the release \
         pull request is opened with a GitHub App installation token (Releases in \
         docs/process.md)"
    )
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The JWT issuer: the client id when set, else the numeric App id. A client id that is set
/// but malformed is an error, not a reason to fall back.
fn read_issuer(client_id: Option<String>, app_id: Option<String>) -> Result<String, String> {
    if let Some(client_id) = non_empty(client_id) {
        let valid = client_id.len() <= CLIENT_ID_MAX_CHARS
            && client_id.chars().all(|c| c.is_ascii_alphanumeric());
        return if valid {
            Ok(client_id)
        } else {
            Err(format!(
                "{CLIENT_ID_VARIABLE} is not a GitHub App client id: letters and digits, at \
                 most {CLIENT_ID_MAX_CHARS}"
            ))
        };
    }
    let Some(app_id) = non_empty(app_id) else {
        return Err(missing_credentials());
    };
    let digits = app_id.len() <= APP_ID_MAX_DIGITS && app_id.chars().all(|c| c.is_ascii_digit());
    match app_id.parse::<u64>() {
        Ok(number) if digits && number > 0 => Ok(number.to_string()),
        _ => Err(format!("{APP_ID_VARIABLE} is not a GitHub App id")),
    }
}

/// Reads the App's client id (or its App id) and private key; the key never appears in an
/// error.
pub fn read_credentials(
    client_id: Option<String>,
    app_id: Option<String>,
    key: Option<String>,
) -> Result<AppCredentials, String> {
    let Some(key) = non_empty(key) else {
        return Err(missing_credentials());
    };
    let issuer = read_issuer(client_id, app_id)?;
    let key = key.as_str();
    if key.len() > PRIVATE_KEY_MAX_BYTES {
        return Err(format!(
            "{APP_KEY_VARIABLE} is larger than {PRIVATE_KEY_MAX_BYTES} bytes"
        ));
    }
    let Ok(key) = EncodingKey::from_rsa_pem(key.as_bytes()) else {
        return Err(format!(
            "{APP_KEY_VARIABLE} is not an RSA private key in PEM form"
        ));
    };
    Ok(AppCredentials { issuer, key })
}

/// `owner/name` from the Actions environment, bounded and limited to GitHub's name characters:
/// an owner is letters, digits and `-`; a name adds `_` and `.` but is never `.` or `..`.
pub fn read_repository(value: Option<String>) -> Result<Repository, String> {
    let value = value.unwrap_or_default();
    let valid_owner = |owner: &str| {
        !owner.is_empty() && owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    let valid_name = |name: &str| {
        !name.is_empty()
            && name != "."
            && name != ".."
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    };
    match value.split_once('/') {
        Some((owner, name))
            if value.len() <= REPOSITORY_MAX_CHARS && valid_owner(owner) && valid_name(name) =>
        {
            Ok(Repository {
                owner: owner.to_string(),
                name: name.to_string(),
            })
        }
        _ => Err(format!(
            "{REPOSITORY_VARIABLE} must be `owner/name`; Actions sets it for every job"
        )),
    }
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| "the system clock is before 1970".to_string())
}

/// The App JWT: `iat` backdated, `exp` exactly [`JWT_MAX_LIFETIME_SECONDS`] after `iat`, and
/// `iss` the client id, or the App id as a string, the JSON web token `StringOrURI` form.
fn app_jwt(credentials: &AppCredentials, now: u64) -> Result<String, String> {
    let issued = now
        .checked_sub(JWT_BACKDATE_SECONDS)
        .ok_or("the system clock is before 1970")?;
    let expires = issued
        .checked_add(JWT_MAX_LIFETIME_SECONDS)
        .ok_or("the JWT expiry overflows")?;
    let claims = serde_json::json!({
        "iat": issued,
        "exp": expires,
        "iss": credentials.issuer,
    });
    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &credentials.key).map_err(|_| {
        format!("{APP_KEY_VARIABLE} could not sign the App JWT; it is not a usable RSA key")
    })
}

/// The parent variables gh may see: where to find itself, a temporary directory and the locale.
/// Everything else, the App's ids and key, `HOME`, proxies and certificate overrides included,
/// stays out of its environment.
fn gh_environment(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    parent
        .into_iter()
        .filter(|(name, _)| GH_INHERITED_VARIABLES.iter().any(|allowed| name == allowed))
        .collect()
}

/// The parent environment minus the App's ids and key, for a child that needs the rest of it.
pub fn without_app_credentials(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    parent
        .into_iter()
        .filter(|(name, _)| {
            name != CLIENT_ID_VARIABLE && name != APP_ID_VARIABLE && name != APP_KEY_VARIABLE
        })
        .collect()
}

/// A command run in an empty private directory, which is also its `GH_CONFIG_DIR`, with the
/// allowlisted parent variables, telemetry off and the credential in `GH_TOKEN`; the arguments
/// carry no secret. Without `HOME`, gh 2.102.0 resolves its state directory relative to the
/// working directory and, with telemetry on, writes a device id there; the private working
/// directory keeps any such write out of the checkout.
fn credentialed_command(
    program: &str,
    credential: &str,
    args: &[&str],
    parent: impl IntoIterator<Item = (OsString, OsString)>,
    config_dir: &Path,
) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(gh_environment(parent))
        .current_dir(config_dir)
        .env("GH_CONFIG_DIR", config_dir)
        .env("GH_TELEMETRY", "disabled")
        .env("GH_TOKEN", credential)
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1");
    command
}

/// A new directory private to this process, so gh reads no configuration that could redirect
/// its requests; created with `create_dir`, which fails rather than reuse an existing path.
fn fresh_config_dir() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let sequence = CONFIG_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let dir = env::temp_dir().join(format!("tycho-gh-{}-{nanos}-{sequence}", process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    Ok(dir)
}

/// Runs `gh api` in an empty private directory, removed afterwards. gh 2.102.0 writes nothing
/// there for an API call with telemetry off; a directory left behind is reported, not fatal, so
/// a token already issued still reaches its revocation.
fn gh_api(credential: &str, args: &[&str]) -> Result<crate::process::Captured, String> {
    let mut gh_args = vec!["api"];
    gh_args.extend_from_slice(args);
    let config_dir = fresh_config_dir()?;
    let captured = run_bounded(
        &mut credentialed_command("gh", credential, &gh_args, env::vars_os(), &config_dir),
        GH_TIMEOUT,
    );
    if let Err(error) = fs::remove_dir(&config_dir) {
        eprintln!(
            "xtask: gh left files in {}; not removed: {error}",
            config_dir.display()
        );
    }
    Ok(captured)
}

fn decode_installation(exit: Exit, stdout: &str) -> InstallationOutcome {
    if exit != Exit::Code(0) {
        return InstallationOutcome::Failed(exit);
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout.trim()) else {
        return InstallationOutcome::Unrecognised("installation response is not JSON");
    };
    match value.get("id").and_then(serde_json::Value::as_u64) {
        Some(id) if id > 0 => InstallationOutcome::Found(id),
        _ => InstallationOutcome::Unrecognised("installation response has no numeric `id`"),
    }
}

/// The granted permissions must be the requested ones plus GitHub's implicit metadata read.
fn grant_is_exact(permissions: &serde_json::Map<String, serde_json::Value>) -> bool {
    let requested_present = REQUESTED_PERMISSIONS.iter().all(|(name, level)| {
        permissions.get(*name).and_then(serde_json::Value::as_str) == Some(level)
    });
    let nothing_else = permissions.iter().all(|(name, level)| {
        let level = level.as_str();
        REQUESTED_PERMISSIONS
            .iter()
            .chain(std::iter::once(&IMPLICIT_PERMISSION))
            .any(|(allowed, allowed_level)| name == allowed && level == Some(allowed_level))
    });
    requested_present && nothing_else
}

fn single_repository(value: &serde_json::Value, repository: &Repository) -> bool {
    let names: Option<Vec<&str>> = value
        .get("repositories")
        .and_then(serde_json::Value::as_array)
        .and_then(|list| {
            list.iter()
                .map(|entry| entry.get("name").and_then(serde_json::Value::as_str))
                .collect()
        });
    let selected = value
        .get("repository_selection")
        .and_then(serde_json::Value::as_str)
        == Some("selected");
    selected && names.is_some_and(|names| names == [repository.name.as_str()])
}

fn decode_access_token(exit: Exit, stdout: &str, repository: &Repository) -> TokenOutcome {
    if exit != Exit::Code(0) {
        return TokenOutcome::Failed(exit);
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout.trim()) else {
        return TokenOutcome::Unrecognised("token response is not JSON");
    };
    let token = match value.get("token").and_then(serde_json::Value::as_str) {
        Some(token)
            if !token.is_empty()
                && token.len() <= TOKEN_MAX_CHARS
                && token.chars().all(|c| c.is_ascii_graphic()) =>
        {
            token
        }
        _ => return TokenOutcome::Unrecognised("token response has no usable `token`"),
    };
    let token = InstallationToken(token.to_string());
    let Some(permissions) = value
        .get("permissions")
        .and_then(serde_json::Value::as_object)
    else {
        return TokenOutcome::UnreadableGrant(token);
    };
    if !grant_is_exact(permissions) || !single_repository(&value, repository) {
        return TokenOutcome::Overgranted(token);
    }
    TokenOutcome::Issued(token)
}

fn access_token_args(installation: u64, repository: &Repository) -> Vec<String> {
    let mut args = vec![
        "--method".to_string(),
        "POST".to_string(),
        format!("/app/installations/{installation}/access_tokens"),
        "-f".to_string(),
        format!("repositories[]={}", repository.name),
    ];
    for (name, level) in REQUESTED_PERMISSIONS {
        args.push("-f".to_string());
        args.push(format!("permissions[{name}]={level}"));
    }
    args
}

fn describe_token_failure(outcome: &TokenOutcome) -> String {
    match outcome {
        TokenOutcome::Issued(_) => "token issued".to_string(),
        TokenOutcome::Failed(exit) => format!("gh api for the installation token ended {exit:?}"),
        TokenOutcome::Overgranted(_) => "the issued token's grant is not exactly contents and \
                                         pull requests write on this repository; refusing it"
            .to_string(),
        TokenOutcome::UnreadableGrant(_) => {
            "the token response has no `permissions` object; refusing the token".to_string()
        }
        TokenOutcome::Unrecognised(reason) => reason.to_string(),
    }
}

/// Mints an installation token for `repository`, down-scoped to the requested permissions.
pub fn mint(
    credentials: &AppCredentials,
    repository: &Repository,
) -> Result<InstallationToken, String> {
    let jwt = app_jwt(credentials, unix_now()?)?;
    let lookup_path = format!(
        "/repos/{}/{}/installation",
        repository.owner, repository.name
    );
    let found = gh_api(&jwt, &[lookup_path.as_str()])?;
    let installation = match decode_installation(found.exit, &found.stdout) {
        InstallationOutcome::Found(id) => id,
        InstallationOutcome::Failed(exit) => {
            return Err(format!(
                "the installation lookup for {}/{} ended {exit:?}; the App must be installed on \
                 this repository and the key must belong to the App",
                repository.owner, repository.name
            ))
        }
        InstallationOutcome::Unrecognised(reason) => return Err(reason.to_string()),
    };
    let args = access_token_args(installation, repository);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let issued = gh_api(&jwt, &arg_refs)?;
    let outcome = decode_access_token(issued.exit, &issued.stdout, repository);
    let reason = describe_token_failure(&outcome);
    match outcome {
        TokenOutcome::Issued(token) => Ok(token),
        TokenOutcome::Overgranted(token) | TokenOutcome::UnreadableGrant(token) => {
            Err(match revoke(&token) {
                Ok(()) => format!("{reason}; the token is revoked"),
                Err(revocation) => format!("{reason}; {revocation}"),
            })
        }
        TokenOutcome::Failed(_) | TokenOutcome::Unrecognised(_) => Err(reason),
    }
}

/// Revokes the token so it does not outlive the job that minted it.
pub fn revoke(token: &InstallationToken) -> Result<(), String> {
    let revoked = gh_api(
        token.expose(),
        &["--method", "DELETE", "/installation/token"],
    )?;
    if revoked.exit == Exit::Code(0) {
        Ok(())
    } else {
        Err(format!(
            "revoking the installation token ended {:?}",
            revoked.exit
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::KeyPair as _;
    use jsonwebtoken::{DecodingKey, Validation};

    const NOW: u64 = 1_800_000_000;
    const TOKEN: &str = "ghs_16C7e42F292c6912E7710c838347Ae178B4a";

    /// A fresh key per run, in the `RSA PRIVATE KEY` form GitHub downloads, and its public half.
    fn test_key() -> (String, String) {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = pem::encode(&pem::Pem::new(
            "PRIVATE KEY",
            pair.as_der().unwrap().as_ref(),
        ));
        let pkcs1_der = EncodingKey::from_rsa_pem(pkcs8.as_bytes()).unwrap();
        let pkcs1 = pem::encode(&pem::Pem::new("RSA PRIVATE KEY", pkcs1_der.as_bytes()));
        let public_der = pair.public_key().as_der().unwrap();
        let public = pem::encode(&pem::Pem::new("PUBLIC KEY", public_der.as_ref()));
        (pkcs1, public)
    }

    fn repository() -> Repository {
        read_repository(Some("frits-v/tycho-station".into())).unwrap()
    }

    fn token_response(permissions: &str, repositories: &str) -> String {
        format!(
            r#"{{"token":"{TOKEN}","expires_at":"2026-10-09T12:00:00Z","permissions":{permissions},"repository_selection":"selected","repositories":{repositories}}}"#
        )
    }

    #[test]
    fn app_jwt_header_and_claims_decode_and_verify_against_the_public_key() {
        let (private, public) = test_key();
        assert!(private.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        let credentials = read_credentials(None, Some("123456".into()), Some(private)).unwrap();
        let jwt = app_jwt(&credentials, NOW).unwrap();
        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["iat", "exp", "iss"]);
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &jwt,
            &DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();
        let claim = |name: &str| decoded.claims.get(name).and_then(serde_json::Value::as_u64);
        assert_eq!(
            decoded
                .claims
                .get("iss")
                .and_then(serde_json::Value::as_str),
            Some("123456")
        );
        assert_eq!(claim("iat"), Some(NOW.saturating_sub(JWT_BACKDATE_SECONDS)));
        let expires = claim("exp").unwrap();
        let lifetime = expires.saturating_sub(claim("iat").unwrap());
        assert!(lifetime <= JWT_MAX_LIFETIME_SECONDS, "{lifetime}");
        assert!(expires > NOW && expires.saturating_sub(NOW) < JWT_MAX_LIFETIME_SECONDS);
    }

    #[test]
    fn app_jwt_does_not_verify_against_another_key() {
        let (private, _) = test_key();
        let (_, other_public) = test_key();
        let credentials = read_credentials(None, Some("7".into()), Some(private)).unwrap();
        let jwt = app_jwt(&credentials, NOW).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        let verified = jsonwebtoken::decode::<serde_json::Value>(
            &jwt,
            &DecodingKey::from_rsa_pem(other_public.as_bytes()).unwrap(),
            &validation,
        );
        assert!(verified.is_err());
    }

    #[test]
    fn missing_credentials_name_both_and_the_releases_section() {
        let (private, _) = test_key();
        for (app_id, key) in [
            (None, None),
            (Some("1".to_string()), None),
            (None, Some(private.clone())),
            (Some("  ".to_string()), Some(private.clone())),
            (Some("1".to_string()), Some(" ".to_string())),
        ] {
            let error = read_credentials(None, app_id, key).unwrap_err();
            assert!(error.contains(CLIENT_ID_VARIABLE), "{error}");
            assert!(error.contains("preferred"), "{error}");
            assert!(error.contains(APP_ID_VARIABLE), "{error}");
            assert!(error.contains(APP_KEY_VARIABLE), "{error}");
            assert!(error.contains("Releases"), "{error}");
            assert!(error.contains("`release` environment"), "{error}");
        }
        assert!(read_credentials(None, Some("1".into()), Some(private)).is_ok());
    }

    fn signed_issuer(credentials: &AppCredentials, public: &str) -> Option<String> {
        let jwt = app_jwt(credentials, NOW).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &jwt,
            &DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();
        decoded
            .claims
            .get("iss")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    }

    #[test]
    fn the_client_id_is_the_issuer_when_set_and_the_app_id_is_the_fallback() {
        let (private, public) = test_key();
        let both = read_credentials(
            Some(" Iv23liAbC123 ".into()),
            Some("123456".into()),
            Some(private.clone()),
        )
        .unwrap();
        assert_eq!(
            signed_issuer(&both, &public).as_deref(),
            Some("Iv23liAbC123")
        );
        let client_only =
            read_credentials(Some("Iv23liAbC123".into()), None, Some(private.clone())).unwrap();
        assert_eq!(
            signed_issuer(&client_only, &public).as_deref(),
            Some("Iv23liAbC123")
        );
        for empty_client_id in [None, Some(String::new()), Some("  ".to_string())] {
            let fallback = read_credentials(
                empty_client_id,
                Some("123456".into()),
                Some(private.clone()),
            )
            .unwrap();
            assert_eq!(signed_issuer(&fallback, &public).as_deref(), Some("123456"));
        }
    }

    #[test]
    fn a_malformed_client_id_is_refused_without_falling_back() {
        let (private, _) = test_key();
        let too_long = "a".repeat(CLIENT_ID_MAX_CHARS.saturating_add(1));
        for client_id in [
            "Iv23-li",
            "Iv23 li",
            "Iv23li\u{e9}",
            "Iv23li\"x",
            "Iv.23",
            too_long.as_str(),
        ] {
            let error = read_credentials(
                Some(client_id.into()),
                Some("123456".into()),
                Some(private.clone()),
            )
            .unwrap_err();
            assert!(error.contains(CLIENT_ID_VARIABLE), "{client_id}: {error}");
            assert!(!error.contains(client_id), "{error}");
        }
        let longest = "a".repeat(CLIENT_ID_MAX_CHARS);
        assert!(read_credentials(Some(longest), None, Some(private)).is_ok());
    }

    #[test]
    fn refuses_a_key_that_is_not_pem_and_an_app_id_that_is_not_a_number() {
        let not_pem = "MIIEowIBAAKCAQEA-not-a-pem-key";
        let error = read_credentials(None, Some("1".into()), Some(not_pem.into())).unwrap_err();
        assert!(error.contains("PEM"), "{error}");
        assert!(!error.contains(not_pem));
        let oversized = "x".repeat(PRIVATE_KEY_MAX_BYTES.saturating_add(1));
        assert!(read_credentials(None, Some("1".into()), Some(oversized)).is_err());
        let (private, _) = test_key();
        for app_id in ["abc", "0", "-1", "123456789012345678901"] {
            let refused = read_credentials(None, Some(app_id.into()), Some(private.clone()));
            assert!(refused.is_err(), "{app_id}");
        }
    }

    #[test]
    fn repository_must_be_owner_and_name() {
        assert_eq!(
            repository(),
            Repository {
                owner: "frits-v".into(),
                name: "tycho-station".into()
            }
        );
        for bad in [
            "",
            "tycho-station",
            "/x",
            "x/",
            "a/b c",
            "a/b?x=1",
            "a/..",
            "a/.",
            "../x",
            "./x",
            "a.b/x",
            "a_b/x",
            "a/b/c",
        ] {
            assert!(read_repository(Some(bad.into())).is_err(), "{bad}");
        }
        assert!(read_repository(None).is_err());
    }

    #[test]
    fn installation_decoder_covers_each_state() {
        assert_eq!(
            decode_installation(Exit::Code(0), r#"{"id":42,"app_id":7}"#),
            InstallationOutcome::Found(42)
        );
        assert_eq!(
            decode_installation(Exit::Code(1), r#"{"message":"Not Found"}"#),
            InstallationOutcome::Failed(Exit::Code(1))
        );
        for unrecognised in ["", "not json", "{}", r#"{"id":"42"}"#, r#"{"id":0}"#] {
            assert!(
                matches!(
                    decode_installation(Exit::Code(0), unrecognised),
                    InstallationOutcome::Unrecognised(_)
                ),
                "{unrecognised}"
            );
        }
    }

    #[test]
    fn token_decoder_accepts_only_the_requested_grant() {
        let exact = r#"{"contents":"write","pull_requests":"write","metadata":"read"}"#;
        let one_repository = r#"[{"name":"tycho-station"}]"#;
        assert_eq!(
            decode_access_token(
                Exit::Code(0),
                &token_response(exact, one_repository),
                &repository()
            ),
            TokenOutcome::Issued(InstallationToken(TOKEN.into()))
        );
        let wider =
            r#"{"contents":"write","pull_requests":"write","metadata":"read","workflows":"write"}"#;
        let narrower = r#"{"contents":"write","metadata":"read"}"#;
        let admin = r#"{"contents":"write","pull_requests":"write","metadata":"write"}"#;
        let two_repositories = r#"[{"name":"tycho-station"},{"name":"other"}]"#;
        let unnamed_entry = r#"[{"name":"tycho-station"},{}]"#;
        for (permissions, repositories) in [
            (wider, one_repository),
            (narrower, one_repository),
            (admin, one_repository),
            (exact, two_repositories),
            (exact, unnamed_entry),
            (exact, "[]"),
        ] {
            assert_eq!(
                decode_access_token(
                    Exit::Code(0),
                    &token_response(permissions, repositories),
                    &repository()
                ),
                TokenOutcome::Overgranted(InstallationToken(TOKEN.into())),
                "{permissions} {repositories}"
            );
        }
        let all = token_response(exact, one_repository).replace("selected", "all");
        assert_eq!(
            decode_access_token(Exit::Code(0), &all, &repository()),
            TokenOutcome::Overgranted(InstallationToken(TOKEN.into()))
        );
    }

    #[test]
    fn a_refused_token_travels_in_its_variant_for_revocation() {
        let without_permissions = format!(
            r#"{{"token":"{TOKEN}","repository_selection":"selected","repositories":[{{"name":"tycho-station"}}]}}"#
        );
        assert_eq!(
            decode_access_token(Exit::Code(0), &without_permissions, &repository()),
            TokenOutcome::UnreadableGrant(InstallationToken(TOKEN.into()))
        );
        let permissions_not_an_object = format!(r#"{{"token":"{TOKEN}","permissions":"all"}}"#);
        let refused = decode_access_token(Exit::Code(0), &permissions_not_an_object, &repository());
        assert!(
            matches!(&refused, TokenOutcome::UnreadableGrant(token) if token.expose() == TOKEN),
            "{refused:?}"
        );
        let wider = token_response(
            r#"{"contents":"write","pull_requests":"write","metadata":"read","administration":"write"}"#,
            r#"[{"name":"tycho-station"}]"#,
        );
        let refused = decode_access_token(Exit::Code(0), &wider, &repository());
        assert!(
            matches!(&refused, TokenOutcome::Overgranted(token) if token.expose() == TOKEN),
            "{refused:?}"
        );
        assert!(!describe_token_failure(&refused).contains(TOKEN));
    }

    #[test]
    fn token_decoder_reports_failures_without_the_token_or_key_material() {
        let (private, _) = test_key();
        let key_line = private.lines().nth(1).unwrap().to_string();
        let leaky_failure = format!(
            r#"{{"message":"Bad credentials {TOKEN} {key_line}","documentation_url":"x"}}"#
        );
        let malformed_success = format!(r#"{{"token":"{TOKEN}","permissions":"all"}}"#);
        let bad_token = r#"{"token":"has space","permissions":{}}"#;
        let cases = [
            (Exit::Code(1), leaky_failure.as_str()),
            (Exit::TimedOut, leaky_failure.as_str()),
            (Exit::Code(0), malformed_success.as_str()),
            (Exit::Code(0), bad_token),
            (Exit::Code(0), "not json"),
        ];
        for (exit, stdout) in cases {
            let outcome = decode_access_token(exit, stdout, &repository());
            assert!(!matches!(outcome, TokenOutcome::Issued(_)), "{stdout}");
            let shown = format!("{} {outcome:?}", describe_token_failure(&outcome));
            assert!(!shown.contains(TOKEN), "{shown}");
            assert!(!shown.contains(&key_line), "{shown}");
            assert!(!shown.contains("BEGIN"), "{shown}");
        }
        let issued = InstallationToken(TOKEN.into());
        assert!(!format!("{issued:?}").contains(TOKEN));
        let credentials = read_credentials(None, Some("1".into()), Some(private)).unwrap();
        assert!(!format!("{credentials:?}").contains(&key_line));
    }

    #[test]
    fn token_request_scopes_to_one_repository_and_two_permissions() {
        assert_eq!(
            access_token_args(42, &repository()),
            [
                "--method",
                "POST",
                "/app/installations/42/access_tokens",
                "-f",
                "repositories[]=tycho-station",
                "-f",
                "permissions[contents]=write",
                "-f",
                "permissions[pull_requests]=write",
            ]
        );
    }

    fn parent_with_credentials() -> Vec<(OsString, OsString)> {
        [
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/home/runner"),
            (CLIENT_ID_VARIABLE, "Iv23liExample"),
            (APP_ID_VARIABLE, "123456"),
            (
                APP_KEY_VARIABLE,
                "-----BEGIN RSA PRIVATE KEY-----\nkey-material",
            ),
            ("GITHUB_TOKEN", "workflow-token"),
            ("CARGO_HOME", "/home/runner/.cargo"),
            ("HTTPS_PROXY", "http://proxy.invalid"),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect()
    }

    #[test]
    fn gh_sees_only_allowlisted_variables_and_the_credential() {
        let names: Vec<OsString> = gh_environment(parent_with_credentials())
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, [OsString::from("PATH")]);
        // `env` stands in for gh: this proves what the command builder hands a child, not how
        // gh treats the variables it receives.
        let config_dir = fresh_config_dir().unwrap();
        let mut command = credentialed_command(
            "env",
            "the-credential",
            &[],
            parent_with_credentials(),
            &config_dir,
        );
        assert_eq!(command.get_current_dir(), Some(config_dir.as_path()));
        let shown = run_bounded(&mut command, Duration::from_secs(60));
        fs::remove_dir(&config_dir).unwrap();
        let config_line = format!("GH_CONFIG_DIR={}", config_dir.display());
        assert!(shown.stdout.contains(&config_line), "{}", shown.stdout);
        assert_eq!(shown.exit, Exit::Code(0));
        for present in ["GH_TOKEN=the-credential", "GH_TELEMETRY=disabled"] {
            assert!(
                shown.stdout.contains(present),
                "{present}: {}",
                shown.stdout
            );
        }
        for absent in [
            CLIENT_ID_VARIABLE,
            APP_ID_VARIABLE,
            APP_KEY_VARIABLE,
            "key-material",
            "GITHUB_TOKEN",
            "CARGO_HOME",
            "HOME=",
            "HTTPS_PROXY",
        ] {
            assert!(!shown.stdout.contains(absent), "{absent}: {}", shown.stdout);
        }
    }

    #[test]
    fn each_gh_configuration_directory_is_new_empty_and_private() {
        let first = fresh_config_dir().unwrap();
        let second = fresh_config_dir().unwrap();
        assert_ne!(first, second);
        for dir in [&first, &second] {
            let metadata = fs::symlink_metadata(dir).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o777,
                0o700
            );
            assert_eq!(fs::read_dir(dir).unwrap().count(), 0);
            fs::remove_dir(dir).unwrap();
        }
    }

    #[test]
    fn other_children_inherit_everything_but_the_app_credentials() {
        let names: Vec<OsString> = without_app_credentials(parent_with_credentials())
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            ["PATH", "HOME", "GITHUB_TOKEN", "CARGO_HOME", "HTTPS_PROXY"].map(OsString::from)
        );
    }
}
