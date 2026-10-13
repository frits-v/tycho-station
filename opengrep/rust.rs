fn todo_comments() {
    // ruleid: rust-todo-without-ticket
    // TODO: split the slab pass
    // ruleid: rust-todo-without-ticket
    /// TODO measure the tag before placing it
    // ruleid: rust-todo-without-ticket
    // TODO(#41): split the slab pass
    // ruleid: rust-todo-without-ticket
    //! TODO measure the slab first
    // ruleid: rust-todo-without-ticket
    /* TODO split the slab pass */
    // ok: rust-todo-without-ticket
    // TODO: https://github.com/example/tycho/issues/41
    // ok: rust-todo-without-ticket
    // TODO ABC-12 split the slab pass
    // ok: rust-todo-without-ticket
    /* TODO(ABC-12): split the slab pass */
}

fn history_comments() {
    // ruleid: rust-history-trace-comment
    // The tag previously sat on the layout leg.
    // ruleid: rust-history-trace-comment
    /// This replaces the riser model.
    // ruleid: rust-history-trace-comment
    // The router used to push obstacles out 8 px.
    // ok: rust-history-trace-comment
    // The clearance is used to keep tubes off the slab edge.
    // ok: rust-history-trace-comment
    // A tag lies nearest its own connector.
    // ok: rust-history-trace-comment
    /// Nothing was written before the write failed.
    // ruleid: rust-history-trace-comment
    // The tag was centred before.
}

fn cargo_commands() {
    // ruleid: rust-cargo-build-bypasses-mbx
    run(Command::new("cargo").args(["clippy", "--workspace", "--all-targets"]));
    // ruleid: rust-cargo-build-bypasses-mbx
    run(Command::new("cargo").arg("test"));
    // ruleid: rust-cargo-build-bypasses-mbx
    run("cargo", &["test", "--workspace"]);
    // ruleid: rust-cargo-build-bypasses-mbx
    run(Command::new("cargo").args(&["test"]));
    // ruleid: rust-cargo-build-bypasses-mbx
    run(Command::new("cargo").current_dir(root).args(["build", "--release"]));
    // ok: rust-cargo-build-bypasses-mbx
    run(Command::new("cargo").args(["fmt", "--all", "--check"]));
    // ok: rust-cargo-build-bypasses-mbx
    run("cargo", &["fmt", "--all", "--", "--check"]);
    // ok: rust-cargo-build-bypasses-mbx
    run(Command::new("mbx").args(["build", "--release"]));
}

fn let_bound_cargo_commands() {
    let mut command = Command::new("cargo");
    command.current_dir(root);
    // ruleid: rust-cargo-build-bypasses-mbx
    command.arg("build");
    let mut listing = Command::new("cargo");
    // ok: rust-cargo-build-bypasses-mbx
    listing.args(["metadata", "--no-deps"]);
}

fn git_commands() {
    // ruleid: rust-git-inherits-hook-environment
    run(Command::new("git").args(["init", "-q"]));
    // ruleid: rust-git-inherits-hook-environment
    let status = std::process::Command::new("git").arg("status").status();
    // ruleid: rust-git-inherits-hook-environment
    let mut listing = Command::new("git");
    listing.args(["ls-files"]);
    // ok: rust-git-inherits-hook-environment
    run(git_command().args(["init", "-q"]));
    // ok: rust-git-inherits-hook-environment
    run(Command::new("git").env_clear().args(["init", "-q"]));
    // ok: rust-git-inherits-hook-environment
    let mut cleared = Command::new("git");
    cleared.env_clear();
}

fn git_through_runners(&self) {
    // ruleid: rust-git-inherits-hook-environment
    let head = run_captured(Path::new("git"), &["rev-parse", "HEAD"], &[], COMMAND_TIMEOUT);
    // ruleid: rust-git-inherits-hook-environment
    let status = command::run_status(&PathBuf::from("git"), &["status"], &[], COMMAND_TIMEOUT);
    // ruleid: rust-git-inherits-hook-environment
    let fetched = run_status_capped(&self.git, arguments, &GIT_ENVIRONMENT, &removed, GIT_TIMEOUT, MAX);
    // ruleid: rust-git-inherits-hook-environment
    let read = run_captured_without(Path::new("/usr/bin/git"), &["log"], &[], &[], COMMAND_TIMEOUT);
    // ruleid: rust-git-inherits-hook-environment
    let gone = command::run_detached(Path::new("git"), &["gc"], &[], &[], COMMAND_TIMEOUT);
    // ok: rust-git-inherits-hook-environment
    let scrubbed = run_status_capped(&self.git, arguments, &GIT_ENVIRONMENT, &git_environment_removed(), GIT_TIMEOUT, MAX);
    // ok: rust-git-inherits-hook-environment
    let head = run_captured_without(Path::new("git"), &["rev-parse", "HEAD"], &[], &git_environment_removed(), COMMAND_TIMEOUT);
    // ok: rust-git-inherits-hook-environment
    let version = run_captured(&run.args.binary, &["--version"], &pairs, COMMAND_TIMEOUT);
    // ok: rust-git-inherits-hook-environment
    let digest = run_captured(Path::new("/usr/bin/digest"), &["-a", "sha256"], &[], COMMAND_TIMEOUT);
}

fn git_held_in_a_name(&self, git: &Path) {
    let program = Path::new("git");
    // ruleid: rust-git-inherits-hook-environment
    let head = run_captured(program, &["rev-parse", "HEAD"], &[], COMMAND_TIMEOUT);
    // ruleid: rust-git-inherits-hook-environment
    let status = run_status(git, &["status"], &[], COMMAND_TIMEOUT);
    // ruleid: rust-git-inherits-hook-environment
    let log = command::run_captured(Path::new(GIT), &["log"], &[], COMMAND_TIMEOUT);
    // ruleid: rust-git-inherits-hook-environment
    let from = run_status_from(&self.git, &["status"], Path::new("/"), COMMAND_TIMEOUT, MAX);
    // ruleid: rust-git-inherits-hook-environment
    let from_root = command::run_status_from(Path::new("git"), &["log"], Path::new("/"), COMMAND_TIMEOUT, MAX);
    // ruleid: rust-git-inherits-hook-environment
    let output = Command::new(&self.git).arg("status").output();
    // ruleid: rust-git-inherits-hook-environment
    let fetch = Command::new(self.git).arg("fetch").output();
    // ok: rust-git-inherits-hook-environment
    let scrubbed = run_captured_without(program, &["log"], &[], &git_environment_removed(), COMMAND_TIMEOUT);
    // ok: rust-git-inherits-hook-environment
    let cleared = Command::new(&self.git).env_clear().arg("status").output();
    // ok: rust-git-inherits-hook-environment
    let probe = run_status_from(Path::new(SUDO), &["-n", "true"], Path::new("/"), COMMAND_TIMEOUT, MAX);
    // ok: rust-git-inherits-hook-environment
    let timeout = run_captured(Path::new("cargo"), &["metadata"], &[], GIT_TIMEOUT);
}

fn secret_reads() {
    // ruleid: rust-secret-variable-read-outside-the-store
    let key = env::var(REVIEW.key_variable).ok();
    // ruleid: rust-secret-variable-read-outside-the-store
    let token = std::env::var_os("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    // ruleid: rust-secret-variable-read-outside-the-store
    let secret = env::var(langfuse::SECRET_KEY_VARIABLE);
    // ok: rust-secret-variable-read-outside-the-store
    let key = crate::secrets::read(REVIEW.key_variable);
    // ok: rust-secret-variable-read-outside-the-store
    let repository = env::var("GITHUB_REPOSITORY").ok();
    // ok: rust-secret-variable-read-outside-the-store
    let rule = env::var(anthropic_token::FEDERATION_RULE_VARIABLE).ok();
    // ok: rust-secret-variable-read-outside-the-store
    let public = env::var(langfuse::PUBLIC_KEY_VARIABLE).ok();
    // ok: rust-secret-variable-read-outside-the-store
    let job = env::var("GITHUB_TOKEN").ok();
}

fn secret_output(token: &InstallationToken, context: &Context) {
    // ruleid: rust-secret-printed
    eprintln!("minted {} for {}", token.expose(), context.head);
    // ruleid: rust-secret-printed
    println!("{}", token.expose());
    // ruleid: rust-secret-printed
    writeln!(file, "token={}", token.expose()).unwrap();
    // ok: rust-secret-printed
    println!("reviewed {}", context.head);
    // ok: rust-secret-printed
    client.request(Method::Get, path, token.expose(), None);
}

fn secret_copies(token: &InstallationToken) {
    // ruleid: rust-secret-copied-out-of-its-type
    let copied = token.expose().to_string();
    // ruleid: rust-secret-copied-out-of-its-type
    let owned = token.value.expose().to_owned();
    // ruleid: rust-secret-copied-out-of-its-type
    let from = String::from(token.expose());
    // ruleid: rust-secret-copied-out-of-its-type
    let header = format!("Bearer {}", token.expose());
    // ok: rust-secret-copied-out-of-its-type
    command.env("GIT_TOKEN", token.expose());
}

fn pull_request_refs(number: u64) {
    // ruleid: rust-pull-request-ref
    let head = format!("refs/pull/{number}/head");
    // ruleid: rust-pull-request-ref
    git.args(["fetch", "origin", "refs/pull/7/merge"]);
    // ok: rust-pull-request-ref
    git.args(["fetch", "origin", commit.as_str()]);
    // ok: rust-pull-request-ref
    assert!(!workflow.contains("refs/pull/"));
}
