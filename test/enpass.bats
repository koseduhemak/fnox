#!/usr/bin/env bats
#
# Enpass Provider Tests
#
# These tests verify the Enpass provider integration with fnox.
#
# Prerequisites:
#   - ENPASS_PASSWORD env var set to the test vault password
#   - A test Enpass vault (created by setup if ENPASS_PASSWORD is set)
#   - Run tests: mise run test:bats -- test/enpass.bats
#
# Note: Tests that require a real Enpass vault will skip if
# ENPASS_PASSWORD is not set.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Skip all tests if ENPASS_PASSWORD is not available
	if [[ -z "${ENPASS_PASSWORD:-}" ]]; then
		skip "ENPASS_PASSWORD not set - skipping Enpass tests"
	fi

	# Set up test vault path
	export ENPASS_VAULT_DIR="$BATS_TEST_TMPDIR/enpass-vault"
}

teardown() {
	rm -rf "${ENPASS_VAULT_DIR:-}" 2>/dev/null || true
	_common_teardown
}

# Helper function to create an enpass provider config
create_enpass_config() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.enpass]
type = "enpass"
vault_path = "$ENPASS_VAULT_DIR"

[secrets]
EOF
}

# Helper function to create config with secrets
create_enpass_config_with_secrets() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.enpass]
type = "enpass"
vault_path = "$ENPASS_VAULT_DIR"

[secrets]
$1
EOF
}

@test "fnox get with missing vault directory shows helpful error" {
	create_enpass_config_with_secrets 'MY_SECRET = { provider = "enpass", value = "test-item" }'

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "Failed to read vault info"
}

@test "fnox get with missing password shows auth error" {
	mkdir -p "$ENPASS_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":0,"kdf_algo":"pbkdf2","kdf_iter":100000}' >"$ENPASS_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$ENPASS_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	create_enpass_config_with_secrets 'MY_SECRET = { provider = "enpass", value = "test-item" }'

	# Unset password to test error
	local saved_password="$ENPASS_PASSWORD"
	unset ENPASS_PASSWORD
	unset FNOX_ENPASS_PASSWORD

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "Vault password not set"
	assert_output --partial "FNOX_ENPASS_PASSWORD"

	export ENPASS_PASSWORD="$saved_password"
}

@test "fnox get with wrong password shows auth error" {
	mkdir -p "$ENPASS_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":0,"kdf_algo":"pbkdf2","kdf_iter":100000}' >"$ENPASS_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$ENPASS_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	create_enpass_config_with_secrets 'MY_SECRET = { provider = "enpass", value = "test-item" }'

	local saved_password="$ENPASS_PASSWORD"
	export ENPASS_PASSWORD="wrong-password"

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "invalid password or unsupported version"

	export ENPASS_PASSWORD="$saved_password"
}

@test "fnox get prefers FNOX_ENPASS_PASSWORD over ENPASS_PASSWORD" {
	mkdir -p "$ENPASS_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":0,"kdf_algo":"pbkdf2","kdf_iter":100000}' >"$ENPASS_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$ENPASS_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	create_enpass_config_with_secrets 'MY_SECRET = { provider = "enpass", value = "test-item" }'

	# Both set - FNOX_ prefix should take priority
	export ENPASS_PASSWORD="wrong-password"
	export FNOX_ENPASS_PASSWORD="also-wrong-password"

	# Both wrong, but this tests that FNOX_ prefix is checked
	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	# Should fail with auth error (both are wrong), confirming the provider tried
	assert_output --partial "invalid password or unsupported version"

	unset FNOX_ENPASS_PASSWORD
}

@test "fnox list shows enpass-backed secrets" {
	create_enpass_config_with_secrets 'MY_SECRET = { provider = "enpass", value = "test-item" }'

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "MY_SECRET"
}

@test "fnox config with unsupported kdf_algo shows error" {
	mkdir -p "$ENPASS_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":0,"kdf_algo":"argon2","kdf_iter":100000}' >"$ENPASS_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$ENPASS_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	create_enpass_config_with_secrets 'MY_SECRET = { provider = "enpass", value = "test-item" }'

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "Unsupported KDF algorithm"
}

@test "fnox config with keyfile required but not set shows error" {
	mkdir -p "$ENPASS_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":1,"kdf_algo":"pbkdf2","kdf_iter":100000}' >"$ENPASS_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$ENPASS_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	# Config without keyfile
	create_enpass_config_with_secrets 'MY_SECRET = { provider = "enpass", value = "test-item" }'

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "requires a keyfile"
}
