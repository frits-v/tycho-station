// The session sandbox (design section 7): the system paths every vendor session may read or
// write, and each vendor's network allowlist at the session proxy. The paths are ported from
// the `system_read_*` and `system_write_*` groups of nono-cli 0.80.0's `data/policy.json`,
// less the entries absent on macOS 26 (`/usr/local/lib`, `/private/var/db/dyld`,
// `/var/db/dyld`, `/run`, `/nix`) and the `$TMPDIR` variable, which `/private/var/folders`
// covers. A nono or macOS update re-runs the existence test (docs/process.md, the session
// sandbox).
package config

_macos_read: [
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/lib", "/usr/share",
	"/System/Library", "/Library", "/Library/Frameworks", "/dev", "/var/db", "/private/etc/ssl",
	"/etc/ssl", "/etc", "/private/etc", "/usr/share/zoneinfo", "/usr/share/locale",
	"/var/db/timezone", "/usr/share/terminfo", "/var", "/private/var", "/private", "/tmp",
	"/System/Volumes", "/System/Cryptexes", "/Applications", "/cores", "/opt",
]
_macos_write: ["/private/tmp", "/tmp", "/private/var/folders", "/var/folders", "/dev"]

// Present on every Linux the ci runner uses.
_linux_read: [
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/share", "/etc/hosts",
	"/etc/nsswitch.conf", "/etc/group", "/etc/passwd", "/etc/ssl", "/etc/ld.so.cache",
	"/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime", "/etc/alternatives",
	"/etc/os-release", "/etc/services", "/dev/null", "/dev/zero", "/dev/random",
	"/dev/urandom", "/dev/full", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/fd",
	"/dev/pts", "/proc/self", "/proc/cpuinfo", "/proc/meminfo", "/proc/stat", "/proc/loadavg",
	"/proc/version", "/proc/filesystems", "/run", "/var/run", "/sys", "/tmp",
]
// Entries of nono's Linux list a runner may lack.
_linux_read_optional: [
	"/lib", "/lib64", "/usr/local/bin", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64",
	"/etc/resolv.conf", "/run/systemd/resolve", "/etc/gai.conf", "/etc/pki",
	"/etc/ca-certificates", "/etc/crypto-policies", "/etc/fonts", "/etc/timezone",
	"/etc/locale.conf", "/etc/locale.gen", "/etc/mime.types", "/etc/manpath.config",
	"/etc/man_db.conf", "/var/cache/man", "/run/systemd/userdb", "/usr/share/locale",
	"/usr/share/locale-langpack", "/usr/share/zoneinfo", "/usr/share/terminfo",
	"/usr/share/ca-certificates", "/lib/terminfo", "/etc/terminfo", "/dev/tty",
	"/dev/console",
]
_linux_x86_64: ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"]
_linux_aarch64: ["/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu"]
_linux_write: ["/tmp", "/dev/null", "/dev/zero", "/dev/full", "/dev/stdout", "/dev/stderr", "/dev/fd", "/dev/pts", "/proc/self/fd"]
_linux_write_optional: ["/dev/tty"]

sandbox: #Sandbox & {
	system_paths: [
		for entry in _macos_read {path: entry, access: "read", platform: "macos"},
		for entry in _macos_write {path: entry, access: "write", platform: "macos"},
		for entry in _linux_read {path: entry, access: "read", platform: "linux"},
		for entry in _linux_read_optional {path: entry, access: "read", platform: "linux", optional: true},
		for entry in _linux_x86_64 {path: entry, access: "read", platform: "linux", arch: "x86_64", optional: true},
		for entry in _linux_aarch64 {path: entry, access: "read", platform: "linux", arch: "aarch64", optional: true},
		for entry in _linux_write {path: entry, access: "write", platform: "linux"},
		for entry in _linux_write_optional {path: entry, access: "write", platform: "linux", optional: true},
	]
	vendors: {
		// Claude's telemetry, error reporting and update checks are off through its
		// environment; whatever still tries another host is refused and recorded.
		claude: allowed_hosts: ["api.anthropic.com"]
		codex: allowed_hosts: ["chatgpt.com", "api.openai.com", "auth.openai.com"]
	}
}
