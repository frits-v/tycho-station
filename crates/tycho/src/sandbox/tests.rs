#![expect(
    clippy::disallowed_methods,
    reason = "fixtures live in scratch directories no other user can write"
)]

use super::*;
use crate::config_store::{PORT_OFFSET_BASE, PORT_OFFSET_SLOTS, PORT_OFFSET_STRIDE, PortOffset};

fn config() -> SandboxConfig {
    SandboxConfig::embedded().unwrap().value
}

fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tycho-sandbox-{test}-{}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(dir.join("worktree")).unwrap();
    fs::write(dir.join("brief.md"), "brief").unwrap();
    fs::create_dir_all(dir.join("sockets")).unwrap();
    dir
}

fn plan(dir: &Path, proxy_port: u16, ports: CorePorts) -> SandboxPlan {
    SandboxPlan {
        proxy_port,
        core_ports: core_ports(ports),
        grants: vec![
            Grant {
                path: dir.join("worktree"),
                access: Access::ReadWrite,
            },
            Grant {
                path: dir.join("brief.md"),
                access: Access::Read,
            },
        ],
        socket_dirs: vec![dir.join("sockets")],
        absent_paths: vec![dir.join("absent/.gitconfig")],
        state_files: vec![dir.join("home/.claude.json")],
    }
}

#[test]
fn the_embedded_configuration_decodes_within_its_bounds_and_names_each_vendor_s_hosts() {
    let config = config();
    assert_eq!(
        config.allowed_hosts(SandboxVendor::Claude),
        ["api.anthropic.com"]
    );
    assert_eq!(
        config.allowed_hosts(SandboxVendor::Codex),
        ["chatgpt.com", "api.openai.com", "auth.openai.com"]
    );
    assert!(
        config
            .system_paths
            .iter()
            .all(|grant| grant.platform != Platform::Macos || !grant.optional)
    );
}

/// The re-prove step after a macOS or nono update: every entry of this host's list exists,
/// so no session start fails on a path the update removed. Run on the macOS host and on the
/// Linux ci runner.
#[test]
fn every_system_path_of_this_host_exists() {
    let (platform, arch) = host().unwrap();
    let config = config();
    let mut examined = 0_usize;
    let mut skipped = Vec::new();
    for grant in config.system_paths_for(platform, arch) {
        examined += 1;
        let present = fs::symlink_metadata(&grant.path).is_ok();
        if grant.optional && !present {
            skipped.push(grant.path.display().to_string());
            continue;
        }
        assert!(
            present,
            "{} is in the list but absent",
            grant.path.display()
        );
    }
    assert!(
        examined > skipped.len(),
        "{examined} system paths for {platform:?} {arch:?}, all optional and absent: {skipped:?}"
    );
}

#[test]
fn a_bad_host_or_an_optional_macos_entry_is_refused() {
    let mut bad_host = config();
    bad_host.vendors.claude.allowed_hosts = vec!["api.anthropic.com:443".to_string()];
    assert!(bad_host.check().is_err());
    let mut no_hosts = config();
    no_hosts.vendors.codex.allowed_hosts.clear();
    assert!(no_hosts.check().is_err());
    let mut optional = config();
    let first = optional
        .system_paths
        .iter_mut()
        .find(|grant| grant.platform == Platform::Macos)
        .unwrap();
    first.optional = true;
    assert!(optional.check().is_err());
    for host in ["api.anthropic.com", "auth.openai.com", "a-1.example.io"] {
        assert!(is_host(host), "{host}");
    }
    for host in [
        "localhost",
        "127.0.0.1",
        "API.anthropic.com",
        "a..b",
        "*.openai.com",
    ] {
        assert!(!is_host(host), "{host}");
    }
}

/// Proxy-only on the plan's port, which is none of the core's, with no other TCP grant, no
/// network platform rule and no resolver.
fn assert_holds_the_property(set: &CapabilitySet, proxy_port: u16, ports: CorePorts) {
    assert_eq!(
        set.network_mode(),
        &NetworkMode::ProxyOnly {
            port: proxy_port,
            bind_ports: Vec::new()
        }
    );
    assert!(!core_ports(ports).contains(&proxy_port));
    assert_ne!(proxy_port, 0);
    assert!(set.localhost_ports().is_empty());
    assert!(set.localhost_port_ranges().is_empty());
    assert!(set.tcp_connect_ports().is_empty());
    assert!(set.tcp_bind_ports().is_empty());
    assert!(
        set.platform_rules()
            .iter()
            .all(|rule| !rule.contains("network"))
    );
    assert!(!set.dns_enabled());
}

/// The property of every set the station builds, swept over the ports of every one of the
/// 1800 test core slots and the production ports: a set exists only in proxy-only mode on the
/// plan's port, with no resolver, and never when that port is one of the core's.
#[test]
fn no_set_the_station_builds_leaves_proxy_only_or_reaches_a_core_port() {
    let dir = scratch("property");
    let config = config();
    let mut offsets = vec![CorePorts::PRODUCTION];
    for slot in 0..PORT_OFFSET_SLOTS {
        let value = u32::from(PORT_OFFSET_BASE) + u32::from(slot) * u32::from(PORT_OFFSET_STRIDE);
        offsets.push(CorePorts::at(PortOffset::new(value).unwrap()));
    }
    let (mut built, mut refused) = (0_usize, 0_usize);
    for ports in offsets {
        let mut candidates = core_ports(ports);
        candidates.extend([0, 1, 40_000, 65_535]);
        for proxy_port in candidates {
            let plan = plan(&dir, proxy_port, ports);
            match capability_set(&plan, &config) {
                Ok(set) => {
                    built += 1;
                    assert_holds_the_property(&set, proxy_port, ports);
                }
                Err(SandboxError::NotProxyOnly(_)) => {
                    refused += 1;
                    assert!(proxy_port == 0 || core_ports(ports).contains(&proxy_port));
                }
                Err(other) => panic!("{other}"),
            }
        }
    }
    assert!(
        built > 0 && refused > 0,
        "built {built} sets, refused {refused}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The check catches each way a set could widen past the proxy, so a change to the builder
/// that widened it fails rather than passing unnoticed.
#[test]
fn the_proxy_only_check_refuses_every_widening() {
    let dir = scratch("widening");
    let plan = plan(&dir, 40_000, CorePorts::PRODUCTION);
    let set = capability_set(&plan, &config()).unwrap();
    let widened = [
        set.clone().set_network_mode(NetworkMode::AllowAll),
        set.clone().allow_localhost_port(19_070),
        set.clone()
            .allow_localhost_port_range(19_000, 19_100)
            .unwrap(),
        set.clone().allow_tcp_connect(443),
        set.clone().allow_tcp_bind(8080),
        set.clone().proxy_only_with_bind(40_000, vec![9000]),
        set.clone().proxy_only(41_000),
        set.clone()
            .platform_rule("(allow network-outbound (remote tcp \"localhost:19070\"))")
            .unwrap(),
    ];
    for (index, widened) in widened.iter().enumerate() {
        assert!(
            matches!(
                check_proxy_only(widened, &plan),
                Err(SandboxError::NotProxyOnly(_))
            ),
            "widening {index} passed"
        );
    }
    assert!(check_proxy_only(&set, &plan).is_ok());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_missing_grant_is_a_refusal_never_a_narrower_set() {
    let dir = scratch("missing");
    let mut plan = plan(&dir, 40_000, CorePorts::PRODUCTION);
    plan.grants.push(Grant {
        path: dir.join("never-made"),
        access: Access::Read,
    });
    assert!(matches!(
        capability_set(&plan, &config()),
        Err(SandboxError::Grant { .. })
    ));
    let mut sockets = super::tests::plan(&dir, 40_000, CorePorts::PRODUCTION);
    sockets.socket_dirs.push(dir.join("no-sockets"));
    assert!(matches!(
        capability_set(&sockets, &config()),
        Err(SandboxError::Grant { .. })
    ));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_plan_round_trips_and_one_out_of_bounds_or_with_an_unplain_path_is_refused() {
    let dir = scratch("bounds");
    let plan = plan(&dir, 40_000, CorePorts::PRODUCTION);
    assert_eq!(
        SandboxPlan::from_json(&plan.to_json().unwrap()).unwrap(),
        plan
    );
    let mut many = plan.clone();
    many.grants = vec![many.grants[0].clone(); PLAN_GRANTS_MAX + 1];
    assert!(matches!(many.to_json(), Err(SandboxError::Plan(_))));
    for path in ["relative", "/a/../b", "/a/./b", "/a\"b", "/a\\b", "/a\nb"] {
        let mut unplain = plan.clone();
        unplain.absent_paths = vec![PathBuf::from(path)];
        assert!(
            matches!(unplain.to_json(), Err(SandboxError::Path(_))),
            "{path:?}"
        );
    }
    let long = format!("{{\"x\":\"{}\"}}", "y".repeat(PLAN_MAX_BYTES));
    assert!(matches!(
        SandboxPlan::from_json(&long),
        Err(SandboxError::Plan(_))
    ));
    let unknown = plan.to_json().unwrap().replacen('{', "{\"extra\":1,", 1);
    assert!(SandboxPlan::from_json(&unknown).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn an_absent_path_and_a_state_file_become_one_rule_each_and_nothing_wider() {
    let dir = scratch("absent");
    let plan = plan(&dir, 40_000, CorePorts::PRODUCTION);
    let set = capability_set(&plan, &config()).unwrap();
    let state = dir.join("home/.claude.json").display().to_string();
    let escaped = state.replace('.', "[.]");
    assert_eq!(
        set.platform_rules(),
        [
            format!(
                "(allow file-read-metadata (literal \"{}\"))",
                dir.join("absent/.gitconfig").display()
            ),
            format!("(allow file-read* file-write* (regex \"^{escaped}([.][^/]+)?$\"))"),
        ]
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The sibling pattern of a state file matches what an atomic save writes and renames, and
/// nothing beside the file or below it.
#[test]
fn a_state_file_rule_covers_its_siblings_and_nothing_else() {
    let rule = state_file_rule(Path::new("/Users/agent/.claude.json"));
    assert_eq!(
        rule,
        "(allow file-read* file-write* (regex \"^/Users/agent/[.]claude[.]json([.][^/]+)?$\"))"
    );
    for crafted in [
        "/Users/a[b]/.claude.json",
        "/Users/a^b/.claude.json",
        "/Users/^/.claude.json",
        "/Users/a]/.claude.json",
    ] {
        let mut refused = plan(Path::new("/x"), 40_000, CorePorts::PRODUCTION);
        refused.state_files = vec![PathBuf::from(crafted)];
        assert!(
            matches!(refused.to_json(), Err(SandboxError::Path(_))),
            "{crafted}"
        );
    }
}
