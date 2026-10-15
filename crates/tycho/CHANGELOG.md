# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/frits-v/tycho-station/releases/tag/v0.1.0) - 2026-10-15

### Added

- start launcher sessions as the agent through one sudoers rule ([#121](https://github.com/frits-v/tycho-station/pull/121))
- *(launcher)* the core hands vendor credentials to each session ([#105](https://github.com/frits-v/tycho-station/pull/105))
- shared tool prefix the agent can run but not write ([#101](https://github.com/frits-v/tycho-station/pull/101))
- port offsets for test cores derived from the test home ([#86](https://github.com/frits-v/tycho-station/pull/86))
- claude control session over the inbox socket with a relay ([#61](https://github.com/frits-v/tycho-station/pull/61))
- worktrees from the canonical repository, index and checkpoints ([#62](https://github.com/frits-v/tycho-station/pull/62))
- headless worker vendors for claude and codex with decoders ([#59](https://github.com/frits-v/tycho-station/pull/59))
- blocker path with markdown packets and verdict files ([#60](https://github.com/frits-v/tycho-station/pull/60))
- content-hashed configuration store wired into the spine ([#58](https://github.com/frits-v/tycho-station/pull/58))
- core-side spawn, scrollback and kill for launcher sessions ([#55](https://github.com/frits-v/tycho-station/pull/55))
- launcher with lease, heartbeat, spool and awaitable delivery ([#54](https://github.com/frits-v/tycho-station/pull/54))
- work unit and worker run workflows with the operator gate ([#53](https://github.com/frits-v/tycho-station/pull/53))
- spine services epic, session, reconciler and ports ([#51](https://github.com/frits-v/tycho-station/pull/51))
- code graph port with the entire semantic graph adapter ([#49](https://github.com/frits-v/tycho-station/pull/49))
- synthetic epic repository and harness baseline ([#48](https://github.com/frits-v/tycho-station/pull/48))
- core processes under zmx with the launchd watchdog ([#47](https://github.com/frits-v/tycho-station/pull/47))

### Fixed

- keep a test secret and the launchd uid out of test output ([#116](https://github.com/frits-v/tycho-station/pull/116))
- *(attach)* restore the terminal before sudo; no daemon pipe waits ([#109](https://github.com/frits-v/tycho-station/pull/109))
- scrub git's hook environment before every git spawn ([#102](https://github.com/frits-v/tycho-station/pull/102))
- never follow a symlink under the agent worktree root ([#65](https://github.com/frits-v/tycho-station/pull/65))
- check registry socket and transcript paths and the peer uid ([#68](https://github.com/frits-v/tycho-station/pull/68))

### Other

- define the petition mechanism of article 14 ([#82](https://github.com/frits-v/tycho-station/pull/82))
- *(attach)* a developer tab attaches to an agent-owned zmx session ([#108](https://github.com/frits-v/tycho-station/pull/108))
- *(boundary)* the agent is refused at every boundary, then the gate ([#97](https://github.com/frits-v/tycho-station/pull/97))
- *(control)* bind the stale socket without a listener ([#91](https://github.com/frits-v/tycho-station/pull/91))
- cache builds with mbx and run opengrep rules in ci ([#87](https://github.com/frits-v/tycho-station/pull/87))
- chaos suite for slice zero kills with the first baselines ([#63](https://github.com/frits-v/tycho-station/pull/63))
- release automation with release-plz and cargo-dist through mise ([#50](https://github.com/frits-v/tycho-station/pull/50))
