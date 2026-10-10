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
printf 'FAKE_SECRET_VALUE\n'
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
	assert_output "FAKE_SECRET_VALUE"
	assert_equal "$stderr" ""
}

@test "provider-not-configured error does not echo values from the config file" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
NEIGHBOR = { provider = "plain", value = "FAKE_NEIGHBOR_VALUE" } # FAKE_COMMENT_VALUE
TOKEN = { provider = "missing", value = "FAKE_TOKEN_VALUE" }
EOF

	run --separate-stderr "$FNOX_BIN" get TOKEN
	assert_failure
	assert_output ""
	[[ $stderr == *"Provider 'missing' not configured"* ]]
	[[ $stderr != *"FAKE_NEIGHBOR_VALUE"* ]]
	[[ $stderr != *"FAKE_COMMENT_VALUE"* ]]
	[[ $stderr != *"FAKE_TOKEN_VALUE"* ]]
}

@test "config parse error does not echo values from the config file" {
	cat >fnox.toml <<'EOF'
root = true

[secrets]
NEIGHBOR = { provider = "plain", value = "FAKE_NEIGHBOR_VALUE" }
TOKEN = { provider = "plain", value = "FAKE_TOKEN_VALUE" } trailing
EOF

	run --separate-stderr "$FNOX_BIN" get TOKEN
	assert_failure
	[[ $stderr != *"FAKE_NEIGHBOR_VALUE"* ]]
	[[ $stderr != *"FAKE_TOKEN_VALUE"* ]]
}

@test "config type errors do not echo the offending value" {
	cat >fnox.toml <<'EOF'
root = true

[secrets]
TOKEN = { provider = "plain", value = "x", env = "FAKE_ENV_VALUE" }
EOF

	run --separate-stderr "$FNOX_BIN" get TOKEN
	assert_failure
	[[ $stderr == *"fnox.toml"* ]]
	[[ $stderr != *"FAKE_ENV_VALUE"* ]]
}

@test "malformed config lines do not echo values" {
	cat >fnox.toml <<'EOF'
root = true

[secrets]
A = { provider = "plain", value = "FAKE_DOTTED_VALUE". }
EOF
	run --separate-stderr "$FNOX_BIN" get A
	assert_failure
	[[ $stderr != *"FAKE_DOTTED_VALUE"* ]]

	cat >fnox.toml <<'EOF'
root = true

[secrets]
A = { provider = "plain", value = FAKE_BARE_VALUE }
EOF
	run --separate-stderr "$FNOX_BIN" get A
	assert_failure
	[[ $stderr != *"FAKE_BARE_VALUE"* ]]
}

@test "parser messages and continued lines do not echo values" {
	cat >fnox.toml <<'EOF'
root = true

[secrets]
TOKEN = { provider = "plain", value = "x", if_missing = "x`FAKE_BACKTICK_VALUE" }
EOF
	run --separate-stderr "$FNOX_BIN" get TOKEN
	assert_failure
	[[ $stderr != *"FAKE_BACKTICK_VALUE"* ]]

	printf 'root = true\n\n[secrets]\nTOKEN =\n"FAKE_CONTINUED_VALUE".oops\n' >fnox.toml
	run --separate-stderr "$FNOX_BIN" get TOKEN
	assert_failure
	[[ $stderr != *"FAKE_CONTINUED_VALUE"* ]]
}

@test "secret references and endpoint credentials stay out of provider errors" {
	cat >fnox.toml <<'EOF'
root = true

[providers.op]
type = "1password"

[providers.appconfig]
type = "azure-ac"
endpoint = "http://user:FAKE_URL_SECRET@example.invalid"

[secrets]
REF = { provider = "op", value = "FAKE_REF_VALUE", if_missing = "error" }
URL = { provider = "appconfig", value = "key", if_missing = "error" }
EOF
	run --separate-stderr "$FNOX_BIN" --non-interactive get REF
	assert_failure
	[[ $stderr == *"hidden"* ]]
	[[ $stderr != *"FAKE_REF_VALUE"* ]]

	run --separate-stderr "$FNOX_BIN" --non-interactive get URL
	assert_failure
	[[ $stderr != *"FAKE_URL_SECRET"* ]]
}

@test "secret-not-found errors do not echo the reference" {
	fake_pass <<'EOF'
#!/bin/sh
echo "Error: $2 is not in the password store." >&2
exit 1
EOF
	cat >fnox.toml <<'EOF'
root = true

[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "FAKE_NOTFOUND_REF", if_missing = "error" }
EOF

	run --separate-stderr "$FNOX_BIN" --non-interactive get TOKEN
	assert_failure
	[[ $stderr == *"not found"* ]]
	[[ $stderr != *"FAKE_NOTFOUND_REF"* ]]
}

@test "import parse errors do not echo the input" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"
EOF

	printf '{"TOKEN": "FAKE_JSON_VALUE",}' >input.json
	run --separate-stderr "$FNOX_BIN" import json --dry-run -p plain -i input.json
	assert_failure
	[[ $stderr != *"FAKE_JSON_VALUE"* ]]

	printf '{"PASSWORD": "!@#$%%^&*()_+=", "oops":}' >input.json
	run --separate-stderr "$FNOX_BIN" import json --dry-run -p plain -i input.json
	assert_failure
	[[ $stderr != *'!@#$%^&*()_+='* ]]

	printf 'TOKEN = "FAKE_TOML_VALUE" trailing\n' >input.toml
	run --separate-stderr "$FNOX_BIN" import toml --dry-run -p plain -i input.toml
	assert_failure
	[[ $stderr != *"FAKE_TOML_VALUE"* ]]

	printf 'TOKEN: "FAKE_YAML_VALUE\n  bad: [' >input.yaml
	run --separate-stderr "$FNOX_BIN" import yaml --dry-run -p plain -i input.yaml
	assert_failure
	[[ $stderr != *"FAKE_YAML_VALUE"* ]]
}

@test "edit does not echo decrypted values when the edited file is invalid" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
TOKEN = { provider = "plain", value = "FAKE_EDIT_VALUE" }
EOF
	cat >"$TEST_TEMP_DIR/bin/break-toml" <<'EOF'
#!/bin/sh
printf 'BROKEN = "FAKE_EDIT_VALUE" trailing\n' >>"$1"
EOF
	chmod +x "$TEST_TEMP_DIR/bin/break-toml"

	EDITOR=break-toml run --separate-stderr "$FNOX_BIN" edit
	assert_failure
	[[ $stderr != *"FAKE_EDIT_VALUE"* ]]
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

failing_pass_config() {
	fake_pass <<'EOF'
#!/bin/sh
echo 'Error: could not read FAKE_SECRET_VALUE' >&2
exit 1
EOF
	cat >fnox.toml <<EOF
root = true

[daemon]
enabled = $1

[providers.pass]
type = "password-store"

[secrets]
TOKEN = { provider = "pass", value = "token", if_missing = "error" }
EOF
}

@test "get, exec and export hide provider output when the provider fails" {
	for daemon in false true; do
		failing_pass_config "$daemon"
		for cmd in "get TOKEN" "exec -- true" "export"; do
			# shellcheck disable=SC2086
			run --separate-stderr "$FNOX_BIN" --non-interactive $cmd
			assert_failure
			[[ $stderr == *"hidden"* ]]
			[[ $output != *"FAKE_SECRET_VALUE"* ]]
			[[ $stderr != *"FAKE_SECRET_VALUE"* ]]
		done
	done
}

@test "verbose get shows provider output when the provider fails" {
	failing_pass_config true

	run --separate-stderr "$FNOX_BIN" --non-interactive --verbose get TOKEN
	assert_failure
	assert_output ""
	[[ $stderr == *"could not read FAKE_SECRET_VALUE"* ]]
}

@test "check KEY reports resolvability without printing the value" {
	fake_pass <<'EOF'
#!/bin/sh
printf 'FAKE_SECRET_VALUE\n'
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
	[[ $output != *"FAKE_SECRET_VALUE"* ]]
	[[ $stderr != *"FAKE_SECRET_VALUE"* ]]
}

@test "check KEY fails without relaying provider output" {
	fake_pass <<'EOF'
#!/bin/sh
echo 'Error: could not read FAKE_SECRET_VALUE' >&2
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
	[[ $output != *"FAKE_SECRET_VALUE"* ]]
	[[ $stderr != *"FAKE_SECRET_VALUE"* ]]
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
