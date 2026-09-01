#!/usr/bin/env bash
# Fork release builder for alleneubank/fnox — run from an Apple Silicon Mac.
#
# Builds both fleet platforms from one host and publishes them as a GitHub
# prerelease whose assets are named exactly like upstream's, so the dotfiles
# mise pin only changes owner and version:
#   - aarch64-apple-darwin      native `cargo build --release`
#   - x86_64-unknown-linux-gnu  `cross` (Docker), same as upstream's release.yml
#
# A macOS-only cut breaks the fleet: Linux hosts fail `mise install` when the
# shared pin has no Linux asset. --publish refuses until both archives exist.
#
# Shape: https://gist.github.com/alleneubank/bf7d25542a49b136671db0e4bb65226d
# See also: FORK.md
#
# Usage:
#   ./scripts/release-fork.sh                 # dry-run: print the plan
#   ./scripts/release-fork.sh --run           # build both platforms, stage archives
#   ./scripts/release-fork.sh --run --publish # build, then tag + gh prerelease
#   ./scripts/release-fork.sh --check-fleet   # verify staged archives only
#   ./scripts/release-fork.sh --publish       # publish already-staged archives
#
# Prerequisites (Mac arm64):
#   - clean git tree at the commit you intend to ship
#   - stable Rust toolchain plus the Linux host toolchain cross mounts:
#       rustup toolchain install stable-x86_64-unknown-linux-gnu \
#         --profile minimal --force-non-host
#   - cross (`cargo binstall cross`) and a running Docker engine (OrbStack)
#   - gh authenticated for github.com/alleneubank/fnox
set -euo pipefail

REPO="${FORK_REPO:-alleneubank/fnox}"
FORK_REMOTE="${FORK_REMOTE:-fork_remote}"
FORK_REQUIRED_PLATFORMS="${FORK_REQUIRED_PLATFORMS:-aarch64-apple-darwin,x86_64-unknown-linux-gnu}"
BIN="fnox"
MACOS_TARGET="aarch64-apple-darwin"
LINUX_TARGET="x86_64-unknown-linux-gnu"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DIST="$ROOT/target/fork-release"

usage() {
	sed -n '2,31p' "$0"
}

die() {
	echo "$*" >&2
	exit 1
}

RUN_CONFIRMED=false
PUBLISH_CONFIRMED=false
MODE="plan"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--run)
		RUN_CONFIRMED=true
		MODE="run"
		shift
		;;
	--publish)
		PUBLISH_CONFIRMED=true
		if [[ "$MODE" != "run" ]]; then MODE="publish"; fi
		shift
		;;
	--check-fleet)
		MODE="check-fleet"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown arg: $1 (try --run | --publish | --check-fleet)" ;;
	esac
done

# ── identity ──────────────────────────────────────────────────────────────

# Base is the nearest plain upstream release tag. Fork tags (v<base>-fork.…)
# are filtered out so the version never doubles once they accumulate.
upstream_base() {
	local tag
	while IFS= read -r tag; do
		if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			echo "${tag#v}"
			return 0
		fi
	done < <(git tag --list 'v*' --sort=-v:refname --format='%(refname:short)')
	return 1
}

BASE="$(upstream_base)" || die "no plain upstream release tag found (fetch source_remote --tags)"
VERSION="${BASE}-fork.$(date -u +%Y%m%d).g$(git rev-parse --short=9 HEAD)"
TAG="v${VERSION}"
MACOS_ARCHIVE="${BIN}-${MACOS_TARGET}.tar.gz"
LINUX_ARCHIVE="${BIN}-${LINUX_TARGET}.tar.gz"

# ── helpers ───────────────────────────────────────────────────────────────

require_clean_tree() {
	[[ -z "$(git status --porcelain)" ]] ||
		die "dirty tree — commit or stash before release (the tag must reproduce the artifact)"
}

require_macos_builder() {
	[[ "$(uname -s)" == Darwin ]] || die "fork releases are built on macOS (Apple Silicon)"
	[[ "$(uname -m)" == arm64 ]] || die "fork releases are built on Apple Silicon (arm64)"
	command -v cross >/dev/null 2>&1 || die "cross is required for the Linux build (cargo binstall cross)"
	command -v docker >/dev/null 2>&1 || die "docker is required for the Linux build (OrbStack)"
	docker info >/dev/null 2>&1 || die "Docker engine not reachable — start OrbStack / Docker Desktop"
}

list_present_platforms() {
	local f base
	for f in "$DIST/${BIN}"-*.tar.gz; do
		[[ -e "$f" ]] || continue
		base="$(basename "$f" .tar.gz)"
		echo "${base#"${BIN}"-}"
	done | sort -u
}

missing_required_platforms() {
	local present required p
	present=" $(list_present_platforms | tr '\n' ' ') "
	IFS=',' read -r -a required <<<"$FORK_REQUIRED_PLATFORMS"
	for p in "${required[@]}"; do
		p="${p//[[:space:]]/}"
		[[ -n "$p" ]] || continue
		[[ "$present" == *" $p "* ]] || echo "  - $p"
	done
}

require_fleet_complete() {
	local missing
	missing="$(missing_required_platforms || true)"
	if [[ -n "$missing" ]]; then
		echo "refusing: fleet platforms incomplete" >&2
		echo "required: ${FORK_REQUIRED_PLATFORMS}" >&2
		echo "present:  $(list_present_platforms | tr '\n' ' ')" >&2
		echo "missing:" >&2
		echo "$missing" >&2
		exit 1
	fi
}

write_checksums() {
	(
		cd "$DIST"
		shasum -a 256 "${BIN}"-*.tar.gz | awk '{print $1"  "$2}' >checksums.txt
	)
}

# stage_binary <binary-path> <target> <expected `file` substring>
stage_binary() {
	local bin_src="$1" target="$2" expect="$3" archive stage identity
	archive="${BIN}-${target}.tar.gz"
	[[ -x "$bin_src" ]] || die "missing binary: $bin_src"
	identity="$(file "$bin_src")"
	[[ "$identity" == *"$expect"* ]] ||
		die "platform mismatch: archive wants $target, binary is: $identity"
	stage="$(mktemp -d)"
	install -m 0755 "$bin_src" "$stage/$BIN"
	tar -C "$stage" -czf "$DIST/$archive" "$BIN"
	rm -rf "$stage"
	echo "staged $DIST/$archive"
}

# ── build ─────────────────────────────────────────────────────────────────

build_macos() {
	echo "Building ${VERSION} for ${MACOS_TARGET} (native cargo)..."
	cargo build --release --locked
	stage_binary "$ROOT/target/release/$BIN" "$MACOS_TARGET" "arm64"
}

build_linux() {
	echo "Building ${VERSION} for ${LINUX_TARGET} (cross)..."
	# The cross image is amd64-only; on Apple Silicon Docker must default to
	# linux/amd64 (Rosetta/qemu) or the image manifest lookup fails.
	DOCKER_DEFAULT_PLATFORM=linux/amd64 cross build --release --locked --target "$LINUX_TARGET"
	stage_binary "$ROOT/target/$LINUX_TARGET/release/$BIN" "$LINUX_TARGET" "x86-64"
}

build_all() {
	require_clean_tree
	require_macos_builder
	rm -rf "$DIST"
	mkdir -p "$DIST"
	build_macos
	build_linux
	write_checksums
	require_fleet_complete
	echo
	echo "Built fleet-complete set for ${VERSION}:"
	list_present_platforms | sed 's/^/  - /'
	cat "$DIST/checksums.txt"
}

# ── publish ───────────────────────────────────────────────────────────────

publish_release() {
	require_clean_tree
	require_fleet_complete
	write_checksums
	git rev-parse "$TAG" >/dev/null 2>&1 && die "tag $TAG already exists locally"

	local archives=()
	local f
	for f in "$DIST/${BIN}"-*.tar.gz; do
		archives+=("$f")
	done

	echo
	echo "Publishing prerelease ${TAG} to github.com/${REPO} via remote ${FORK_REMOTE}"
	echo "  platforms: $(list_present_platforms | tr '\n' ' ')"
	echo "  assets:"
	printf '    %s\n' "${archives[@]##*/}" checksums.txt

	git tag -a "$TAG" -m "fork release ${VERSION}"
	git push "$FORK_REMOTE" "refs/tags/${TAG}"

	local notes
	notes="$(mktemp)"
	cat >"$notes" <<NOTES
Personal fork of jdx/fnox for fleet dogfood. Base: upstream v${BASE} tree at
\`$(git rev-parse --short=9 HEAD)\` plus the commits listed in FORK.md.

\`fnox --version\` reports the upstream base (\`${BASE}\`); the fork tag is the
provenance, and mise pins it exactly.

## Fleet platforms

- required: \`${FORK_REQUIRED_PLATFORMS}\`
- shipped: \`$(list_present_platforms | paste -sd, -)\`

## Install (mise)

\`\`\`toml
"github:alleneubank/fnox" = { version = "${VERSION}" }
\`\`\`

Then \`mise lock\` and commit \`config.toml\` + \`mise.lock\` together.
NOTES

	gh release create "$TAG" \
		--repo "$REPO" \
		--prerelease \
		--title "$VERSION" \
		--notes-file "$notes" \
		"${archives[@]}" \
		"$DIST/checksums.txt"
	rm -f "$notes"
	echo "published: https://github.com/${REPO}/releases/tag/${TAG}"
}

# ── plan (dry-run) ────────────────────────────────────────────────────────

print_plan() {
	cat <<PLAN
Fork release plan (dry-run — no build, no publish)

  host:       $(uname -s) $(uname -m)  (must be Darwin arm64 for --run)
  commit:     $(git rev-parse --short=12 HEAD)
  base:       ${BASE}
  version:    ${VERSION}
  tag:        ${TAG}
  repo:       ${REPO} (remote ${FORK_REMOTE})
  required:   ${FORK_REQUIRED_PLATFORMS}
  dist:       ${DIST}

  builds (from this Mac):
    1. ${MACOS_TARGET}       native cargo build --release --locked
    2. ${LINUX_TARGET}  cross build --release --locked --target ${LINUX_TARGET}

  archives:
    - ${MACOS_ARCHIVE}
    - ${LINUX_ARCHIVE}
    - checksums.txt

Next steps:
  ./scripts/release-fork.sh --run              # build both platforms
  ./scripts/release-fork.sh --publish          # tag + gh prerelease (boundary)

After publish: bump "github:alleneubank/fnox" in dotfiles config.toml to
${VERSION}, run mise lock, commit config.toml + mise.lock together.
PLAN
}

# ── main ──────────────────────────────────────────────────────────────────

case "$MODE" in
plan)
	print_plan
	;;
check-fleet)
	echo "version:  ${VERSION}"
	echo "required: ${FORK_REQUIRED_PLATFORMS}"
	echo "present:  $(list_present_platforms | tr '\n' ' ')"
	require_fleet_complete
	echo "ok — fleet set complete"
	cat "$DIST/checksums.txt" 2>/dev/null || true
	;;
run)
	[[ "$RUN_CONFIRMED" == true ]] || die "internal: --run required"
	build_all
	if [[ "$PUBLISH_CONFIRMED" == true ]]; then
		publish_release
	else
		echo
		echo "staged. To publish: ./scripts/release-fork.sh --publish"
	fi
	;;
publish)
	[[ "$PUBLISH_CONFIRMED" == true ]] || die "internal: --publish required"
	publish_release
	;;
esac
