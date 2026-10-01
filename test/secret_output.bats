#!/usr/bin/env bats

# Secret values reach stdout only when a command was asked to print them.
# Diagnostics on stderr must stay value-free.

bats_require_minimum_version 1.5.0

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export XDG_RUNTIME_DIR="$TEST_TEMP_DIR/runtime"
	mkdir -p "$XDG_RUNTIME_DIR" "$TEST_TEMP_DIR/bin"
	export PATH="$TEST_TEMP_DIR/bin:$PATH"
}

teardown() {
	"$FNOX_BIN" daemon stop >/dev/null 2>&1 || true
	_common_teardown
}

fake_pass() {
	cat >"$TEST_TEMP_DIR/bin/pass"
	chmod +x "$TEST_TEMP_DIR/bin/pass"
}

@test "get prints the value on stdout and nothing on stderr" {
	fake_pass <<'EOF'
#!/bin/sh
printf 'fake-secret-value\n'
EOF
	cat >fnox.toml <<'EOF'
root = true

[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "token" }
EOF

	run --separate-stderr "$FNOX_BIN" get TOKEN
	assert_success
	assert_output "fake-secret-value"
	assert_equal "$stderr" ""
}

@test "provider-not-configured error does not echo values from the config file" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
NEIGHBOR = { provider = "plain", value = "fake-neighbor-value" } # fake-comment-value
TOKEN = { provider = "missing", value = "fake-token-value" }
EOF

	run --separate-stderr "$FNOX_BIN" get TOKEN
	assert_failure
	assert_output ""
	[[ $stderr == *"Provider 'missing' not configured"* ]]
	[[ $stderr != *"fake-neighbor-value"* ]]
	[[ $stderr != *"fake-comment-value"* ]]
	[[ $stderr != *"fake-token-value"* ]]
}

@test "config parse error does not echo values from the config file" {
	cat >fnox.toml <<'EOF'
root = true

[secrets]
NEIGHBOR = { provider = "plain", value = "fake-neighbor-value" }
TOKEN = { provider = "plain", value = "fake-token-value" } trailing
EOF

	run --separate-stderr "$FNOX_BIN" get TOKEN
	assert_failure
	[[ $stderr != *"fake-neighbor-value"* ]]
	[[ $stderr != *"fake-token-value"* ]]
}

@test "daemon get fails non-zero when the provider fails in non-interactive mode" {
	fake_pass <<'EOF'
#!/bin/sh
echo 'Error: provider unavailable' >&2
exit 1
EOF
	cat >fnox.toml <<'EOF'
root = true

[daemon]
enabled = true

[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "token" }
EOF

	run --separate-stderr "$FNOX_BIN" --non-interactive get TOKEN
	assert_failure
	assert_output ""
	[[ $stderr == *"command failed"* ]]
}

@test "check KEY reports resolvability without printing the value" {
	fake_pass <<'EOF'
#!/bin/sh
printf 'fake-secret-value\n'
EOF
	cat >fnox.toml <<'EOF'
root = true

[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "token", if_missing = "ignore" }
EOF

	run --separate-stderr "$FNOX_BIN" check TOKEN
	assert_success
	assert_output --partial "TOKEN"
	[[ $output != *"fake-secret-value"* ]]
	[[ $stderr != *"fake-secret-value"* ]]
}

@test "check KEY fails without relaying provider output" {
	fake_pass <<'EOF'
#!/bin/sh
echo 'Error: could not read fake-secret-value' >&2
exit 1
EOF
	cat >fnox.toml <<'EOF'
root = true

[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "token" }
EOF

	run --separate-stderr "$FNOX_BIN" check TOKEN
	assert_failure
	[[ $stderr == *"TOKEN"* ]]
	[[ $output != *"fake-secret-value"* ]]
	[[ $stderr != *"fake-secret-value"* ]]
}

@test "check KEY fails for an undefined secret" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
TOKEN = { provider = "plain", value = "x" }
EOF

	run --separate-stderr "$FNOX_BIN" check MISSING
	assert_failure
	[[ $stderr == *"MISSING"* ]]
}
