# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.10.2] - 2026-10-12

### Fixed
- The registration reachability check no longer fails with `TypeError` before
  reaching the network. Connection timeouts are passed in `connect_args` under
  the driver's own keyword (`connect_timeout`, `tcp_connect_timeout`,
  `timeout`/`login_timeout`), so Oracle, PostgreSQL, MySQL, and MSSQL checks
  now genuinely test the database (#29)
- SQLAlchemy is capped below 2.1: the 2.1 release switched the bare
  `postgresql://` dialect default from psycopg2 to psycopg v3, which broke
  fresh installs with `ModuleNotFoundError` (#30). The deliberate migration is
  tracked in #31

### Changed
- The redaction test asserts the real invariant: the password, the credentials
  pair, and the full URL never appear in check errors. Usernames may appear,
  because database servers quote them in their own authentication failures and
  this project's redaction policy deliberately keeps usernames visible

## [v0.10.1] - 2026-10-12

### Fixed
- `vault_update_connection` now runs the reachability check against the merged
  configuration before writing, with `skip_check` and `force_save` matching the
  registration tools. A bad rotation fails at update time instead of at the
  next query (#27)
- `VaultStore.update` docstring corrected: `None` means "leave unchanged";
  clearing a field requires an empty string
- Release tooling repaired after the v0.10.0 bump overwrote ruff's
  `target-version` and mypy's `python_version`: the version substitution is now
  anchored to the project key and fails loudly without exactly one match, the
  changelog promotion preserves accumulated entries, and `uv.lock` is kept in
  sync with each release

### Changed
- The test suite no longer writes a `./db` file into the repository root, and
  the gitignore entry that masked it was removed so any regression is visible

## [v0.10.0] - 2026-10-12

### Features
- Connection reachability check during vault registration, with an explicit
  save-anyway fallback when the target is unreachable (#20)
- Partial update of an existing vault connection via `vault_update_connection`,
  so a single field such as the password can be rotated on its own (#21)

### Fixed
- Cached engines are now invalidated and disposed on vault mutation, so
  revoking or rotating a credential takes effect without a server restart.
  Previously `vault_revoke` reported success while an authenticated connection
  pool stayed usable, and `overwrite=true` rotation silently did nothing (#22)
- `VaultStore.delete` no longer reports a clean revocation when the OS
  credential manager refused to delete the secret (#22)
- The registration reachability check disposes its throwaway engine, which
  previously leaked a connection pool per check (#22)

### Dependencies
- chore(deps): bump pyjwt (#19)
- chore(deps): bump anyio in the uv group across 1 directory (#18)

## [v0.9.0] - 2026-08-24

### Fixed
- fix(#16): fixing security findings in cryptography (#17)
- fix(vault,server): recognize modern macOS keychain and silence mcp settings warning (#15)

## [v0.8.1] - 2026-08-24

### Fixed
- fix(connections): treat oracle url path as service name (#13)

## [v0.8.0] - 2026-08-24

### Fixed
- fix(vault): apply stored credentials when building engines (#11)

### Documentation
- docs: make binary setup the default (#9)

## [v0.7.1] - 2026-08-23

### Documentation
- docs: make binary setup the default (#9)

## [v0.7.0] - 2026-08-23

### Fixed
- fix(vault): recognize current secret service backend (#7)

## [v0.6.0] - 2026-08-19

### Features
- feat(cli): expose version and update notices (#5)

### Fixed
- fix(deps): cap MCP dependency at version 1 (#4)

## [v0.5.0] - 2026-08-19

### Dependencies
- chore(deps): bump mcp in the uv group across 1 directory (#1)

## [v0.4.0] - 2026-08-19

### Breaking Changes
- feat!: rename project to securedblink

### Features
- feat: add credential vault for secure connection storage
- feat: add structured logging configuration for db-mcp

### Documentation
- docs: Create LICENSE
- docs: add CONTRIBUTING, SECURITY, and CODE_OF_CONDUCT
- docs: rewrite README with stronger structure and copy
- docs: use run.sh as the launcher in README, explain why

### Technical
- chore: comply with Python 3.12+ standards and fix broken environment
- refactor: Refactor code structure for improved readability and maintainability
- ci(release): publish verified artifacts through release workflow

### Testing
- test: adding tests to improve coverage
- test: updating tests

## [v0.3.0] - 2026-08-17

### Features
- feat: add credential vault for secure connection storage
- feat: add structured logging configuration for db-mcp

## [v0.2.0] - 2026-08-17

### Technical
- chore: comply with Python 3.12+ standards and fix broken environment
- refactor: Refactor code structure for improved readability and maintainability

## [v0.1.0] - 2026-06-22

### Initial Release
- chore: initial version
- test: adding tests to improve coverage
- docs: Create LICENSE
- docs: add CONTRIBUTING, SECURITY, and CODE_OF_CONDUCT
- docs: rewrite README with stronger structure and copy
- docs: use run.sh as the launcher in README, explain why

[Unreleased]: https://github.com/paulushcgcj/securedblink/compare/v0.10.2...HEAD
[v0.10.2]: https://github.com/paulushcgcj/securedblink/compare/v0.10.1...v0.10.2
[v0.10.1]: https://github.com/paulushcgcj/securedblink/compare/v0.10.0...v0.10.1
[v0.10.0]: https://github.com/paulushcgcj/securedblink/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/paulushcgcj/securedblink/compare/v0.8.1...v0.9.0
[v0.8.1]: https://github.com/paulushcgcj/securedblink/compare/v0.8.0...v0.8.1
[v0.8.0]: https://github.com/paulushcgcj/securedblink/compare/v0.7.1...v0.8.0
[v0.7.1]: https://github.com/paulushcgcj/securedblink/compare/v0.7.0...v0.7.1
[v0.7.0]: https://github.com/paulushcgcj/securedblink/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/paulushcgcj/securedblink/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/paulushcgcj/securedblink/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/paulushcgcj/securedblink/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/paulushcgcj/securedblink/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/paulushcgcj/securedblink/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/paulushcgcj/securedblink/releases/tag/v0.1.0