# Fork maintenance (`alleneubank/fnox`)

Personal fork of [jdx/fnox](https://github.com/jdx/fnox) for fleet dogfood via
the dotfiles mise pin (`github:alleneubank/fnox`).

`main` is the dogfood tip: upstream `main` plus unmarked upstream-bound commits
plus `[fork]`-prefixed distribution plumbing. Upstream PRs come from a small
branch off `source_remote/main` carrying only the unmarked commits; never PR
`main` as-is.

Remotes are roles: `source_remote` is jdx/fnox, `fork_remote` is this repo.

## Carried commits

Secret-output guard (keeps secret values out of fnox diagnostics; not yet
proposed upstream):

- `fix(config): keep config values out of error source snippets`
- `fix(daemon): fail single-secret resolution when the provider fails`
- `feat(check): check named secrets without printing values`
- `fix(provider): hide relayed provider output in errors unless --verbose`
- `fix(config): mask values in parse errors for config, import and edit`
- `fix: keep credentials out of lease warnings, debug logs and auth prompts`
- `fix: close review bypasses in secret masking and verbose output`
- `fix: keep secret references out of not-found errors, logs and auth prompts`

`fix(daemon): anchor spawned daemon cwd at filesystem root` was dropped after
upstream shipped the same fix in jdx/fnox#795 (v1.35.0).

Rebase `main` onto `source_remote/main` when upstream moves; drop a carried
commit once upstream ships it.

## Fleet platforms (required)

| Asset                                  | Built by                                          |
| -------------------------------------- | ------------------------------------------------- |
| `fnox-aarch64-apple-darwin.tar.gz`     | native `cargo build --release` on Apple Silicon   |
| `fnox-x86_64-unknown-linux-gnu.tar.gz` | `cross` in Docker, as upstream's release.yml does |

Asset names match upstream exactly, so the mise pin changes only owner and
version. mise maps `linux-x64-musl` onto the gnu asset, as it does for the
other forks. A macOS-only release is not fleet-ready; the script refuses
`--publish` until both archives exist.

## Release from a Mac

Prerequisites: clean tree at the commit to ship, stable Rust, the Linux host
toolchain cross mounts (`rustup toolchain install stable-x86_64-unknown-linux-gnu
--profile minimal --force-non-host`), `cross`, a running Docker engine
(OrbStack), and `gh` authenticated for `alleneubank/fnox`.

```sh
./scripts/release-fork.sh            # plan
./scripts/release-fork.sh --run      # build both platforms into target/fork-release/
./scripts/release-fork.sh --publish  # tag + GitHub prerelease (deliberate boundary)
```

Version scheme: `<upstream-base>-fork.<YYYYMMDD>.g<sha9>`, tagged `v<version>`
as a **prerelease** so it never shadows upstream `latest`. The base is the
nearest plain upstream tag; fork tags are filtered out so the version never
doubles.

`fnox --version` reports the upstream base version: fnox embeds
`CARGO_PKG_VERSION` at compile time and stamping it would need a source edit.
The fork tag is the provenance and mise pins it exactly.

## Consume (dotfiles / mise)

```toml
# config/.config/mise/config.toml
"github:alleneubank/fnox" = { version = "<version-without-v-prefix>" }
```

Then on the lock-author host: `mise lock`, and commit `config.toml` +
`mise.lock` together. Prereleases are invisible to `mise up`/`outdated`, so the
bump is always a hand-edited exact tag.
