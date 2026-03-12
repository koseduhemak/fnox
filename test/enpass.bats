#!/usr/bin/env bats
#
# Enpass Provider Tests
#
# These tests verify the Enpass provider integration with fnox,
# including vault decryption, field access, and filtering.
#
# Prerequisites:
#   - Run tests: mise run test:bats -- test/enpass.bats
#
# The tests use two vault fixtures:
#   - test/fixtures/enpass-vault/       — real vault (1 item, password from ENPASS_PASSWORD env)
#   - test/fixtures/enpass-test-vault/  — generated vault (9 items, password: test-vault-password)
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Generated test vault (always available, self-contained)
	export TEST_VAULT_DIR="$PROJECT_ROOT/test/fixtures/enpass-test-vault"
	export TEST_VAULT_PASSWORD="test-vault-password"

	# Mock vault directory for error-handling tests
	export MOCK_VAULT_DIR="$BATS_TEST_TMPDIR/mock-enpass-vault"
}

teardown() {
	rm -rf "${MOCK_VAULT_DIR:-}" 2>/dev/null || true
	_common_teardown
}

# Helper: create config pointing at the generated test vault
create_test_vault_config() {
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.enpass]
type = "enpass"
vault_path = "$TEST_VAULT_DIR"

[secrets]
$1
EOF
	export ENPASS_PASSWORD="$TEST_VAULT_PASSWORD"
}

# Helper: create config pointing at a mock vault (for error tests)
create_mock_vault_config() {
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.enpass]
type = "enpass"
vault_path = "$MOCK_VAULT_DIR"

[secrets]
$1
EOF
}

# ─── Error Handling Tests ───────────────────────────────────────────────────

@test "enpass: missing vault directory shows helpful error" {
	create_mock_vault_config 'MY_SECRET = { provider = "enpass", value = "test-item" }'
	export ENPASS_PASSWORD="dummy"

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "Failed to read vault info"
}

@test "enpass: missing password shows auth error" {
	mkdir -p "$MOCK_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":0,"kdf_algo":"pbkdf2","kdf_iter":100000}' >"$MOCK_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$MOCK_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	create_mock_vault_config 'MY_SECRET = { provider = "enpass", value = "test-item" }'

	unset ENPASS_PASSWORD
	unset FNOX_ENPASS_PASSWORD

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "Vault password not set"
	assert_output --partial "FNOX_ENPASS_PASSWORD"
}

@test "enpass: wrong password shows auth error" {
	mkdir -p "$MOCK_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":0,"kdf_algo":"pbkdf2","kdf_iter":100000}' >"$MOCK_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$MOCK_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	create_mock_vault_config 'MY_SECRET = { provider = "enpass", value = "test-item" }'
	export ENPASS_PASSWORD="wrong-password"

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "invalid password or unsupported version"
}

@test "enpass: FNOX_ENPASS_PASSWORD takes priority over ENPASS_PASSWORD" {
	create_test_vault_config 'MY_SECRET = { provider = "enpass", value = "Unique Login/Password" }'

	# Set FNOX_ to the correct password, ENPASS_PASSWORD to wrong
	export ENPASS_PASSWORD="wrong-password"
	export FNOX_ENPASS_PASSWORD="$TEST_VAULT_PASSWORD"

	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "unique-pass-789"

	unset FNOX_ENPASS_PASSWORD
}

@test "enpass: unsupported kdf_algo shows error" {
	mkdir -p "$MOCK_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":0,"kdf_algo":"argon2","kdf_iter":100000}' >"$MOCK_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$MOCK_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	create_mock_vault_config 'MY_SECRET = { provider = "enpass", value = "test-item" }'
	export ENPASS_PASSWORD="dummy"

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "Unsupported KDF algorithm"
}

@test "enpass: keyfile required but not configured shows error" {
	mkdir -p "$MOCK_VAULT_DIR"
	echo '{"encryption_algo":"aes-256-cbc","have_keyfile":1,"kdf_algo":"pbkdf2","kdf_iter":100000}' >"$MOCK_VAULT_DIR/vault.json"
	dd if=/dev/urandom of="$MOCK_VAULT_DIR/vault.enpassdb" bs=1024 count=10 2>/dev/null

	create_mock_vault_config 'MY_SECRET = { provider = "enpass", value = "test-item" }'
	export ENPASS_PASSWORD="dummy"

	run "$FNOX_BIN" get MY_SECRET
	assert_failure
	assert_output --partial "requires a keyfile"
}

@test "enpass: non-existent item shows not found error" {
	create_test_vault_config 'MISSING = { provider = "enpass", value = "Does Not Exist" }'

	run "$FNOX_BIN" get MISSING
	assert_failure
	assert_output --partial "not found"
}

@test "enpass: non-existent field shows not found error" {
	create_test_vault_config 'MISSING_FIELD = { provider = "enpass", value = "Unique Login/nonexistent" }'

	run "$FNOX_BIN" get MISSING_FIELD
	assert_failure
	assert_output --partial "not found"
	assert_output --partial "nonexistent"
}

# ─── Basic Get & Decrypt Tests ─────────────────────────────────────────────

@test "enpass: get plaintext field by title/label" {
	create_test_vault_config 'USERNAME = { provider = "enpass", value = "Unique Login/Username" }'

	run "$FNOX_BIN" get USERNAME
	assert_success
	assert_output "unique@example.com"
}

@test "enpass: get encrypted (sensitive) field by title/label" {
	create_test_vault_config 'PASSWORD = { provider = "enpass", value = "Unique Login/Password" }'

	run "$FNOX_BIN" get PASSWORD
	assert_success
	assert_output "unique-pass-789"
}

@test "enpass: get URL field" {
	create_test_vault_config 'URL = { provider = "enpass", value = "Unique Login/URL" }'

	run "$FNOX_BIN" get URL
	assert_success
	assert_output "https://example.com"
}

@test "enpass: title-only reference returns sensitive field" {
	# When no field label is given, the first sensitive (password) field is returned
	create_test_vault_config 'DEFAULT = { provider = "enpass", value = "Unique Login" }'

	run "$FNOX_BIN" get DEFAULT
	assert_success
	assert_output "unique-pass-789"
}

@test "enpass: get plaintext note field" {
	create_test_vault_config 'NOTE = { provider = "enpass", value = "API Key/Note" }'

	run "$FNOX_BIN" get NOTE
	assert_success
	assert_output "sk-12345-secret-api-key"
}

@test "enpass: get credit card encrypted fields" {
	create_test_vault_config '
CARD_NUM = { provider = "enpass", value = "Credit Card/Card Number" }
CARD_CVV = { provider = "enpass", value = "Credit Card/CVV" }
CARD_EXP = { provider = "enpass", value = "Credit Card/Expiry" }
'

	run "$FNOX_BIN" get CARD_NUM
	assert_success
	assert_output "4111111111111111"

	run "$FNOX_BIN" get CARD_CVV
	assert_success
	assert_output "123"

	run "$FNOX_BIN" get CARD_EXP
	assert_success
	assert_output "12/2028"
}

@test "enpass: title matching is case-insensitive" {
	create_test_vault_config 'LOWER = { provider = "enpass", value = "unique login/Password" }'

	run "$FNOX_BIN" get LOWER
	assert_success
	assert_output "unique-pass-789"
}

@test "enpass: field label matching is case-insensitive" {
	create_test_vault_config 'FIELD = { provider = "enpass", value = "Unique Login/password" }'

	run "$FNOX_BIN" get FIELD
	assert_success
	assert_output "unique-pass-789"
}

@test "enpass: trashed items are excluded" {
	create_test_vault_config 'TRASHED = { provider = "enpass", value = "Trashed Item/Password" }'

	run "$FNOX_BIN" get TRASHED
	assert_failure
	assert_output --partial "not found"
}

# ─── Filter: Tag ────────────────────────────────────────────────────────────

@test "enpass filter: disambiguate by single tag" {
	create_test_vault_config '
GH_WORK = { provider = "enpass", value = "GitHub/Password", filter = { tag = "work" } }
GH_PERSONAL = { provider = "enpass", value = "GitHub/Password", filter = { tag = "personal" } }
'

	run "$FNOX_BIN" get GH_WORK
	assert_success
	assert_output "gh-secret-123"

	run "$FNOX_BIN" get GH_PERSONAL
	assert_success
	assert_output "gh-personal-456"
}

@test "enpass filter: disambiguate by tag returns correct username" {
	create_test_vault_config '
WORK_USER = { provider = "enpass", value = "GitHub/Username", filter = { tag = "work" } }
PERSONAL_USER = { provider = "enpass", value = "GitHub/Username", filter = { tag = "personal" } }
'

	run "$FNOX_BIN" get WORK_USER
	assert_success
	assert_output "devuser"

	run "$FNOX_BIN" get PERSONAL_USER
	assert_success
	assert_output "personaluser"
}

@test "enpass filter: multi-tag AND (both tags required)" {
	create_test_vault_config '
DB_PROD = { provider = "enpass", value = "Database/Password", filter = { tag = ["backend", "prod"] } }
DB_DEV = { provider = "enpass", value = "Database/Password", filter = { tag = ["backend", "dev"] } }
'

	run "$FNOX_BIN" get DB_PROD
	assert_success
	assert_output "db-admin-pass"

	run "$FNOX_BIN" get DB_DEV
	assert_success
	assert_output "db-ro-pass"
}

@test "enpass filter: tag is case-insensitive" {
	create_test_vault_config 'SECRET = { provider = "enpass", value = "GitHub/Password", filter = { tag = "WORK" } }'

	run "$FNOX_BIN" get SECRET
	assert_success
	assert_output "gh-secret-123"
}

@test "enpass filter: non-matching tag returns error" {
	create_test_vault_config 'SECRET = { provider = "enpass", value = "GitHub/Password", filter = { tag = "nonexistent" } }'

	run "$FNOX_BIN" get SECRET
	assert_failure
	assert_output --partial "not found"
	assert_output --partial "No items named"
}

# ─── Filter: Category ──────────────────────────────────────────────────────

@test "enpass filter: disambiguate by category" {
	create_test_vault_config 'CC_NUM = { provider = "enpass", value = "Credit Card/Card Number", filter = { category = "creditcard" } }'

	run "$FNOX_BIN" get CC_NUM
	assert_success
	assert_output "4111111111111111"
}

@test "enpass filter: category is case-insensitive" {
	create_test_vault_config 'CC = { provider = "enpass", value = "Credit Card/CVV", filter = { category = "CREDITCARD" } }'

	run "$FNOX_BIN" get CC
	assert_success
	assert_output "123"
}

# ─── Filter: Favorite ──────────────────────────────────────────────────────

@test "enpass filter: filter by favorite=true" {
	create_test_vault_config 'FAV = { provider = "enpass", value = "API Key/Note", filter = { favorite = "true" } }'

	run "$FNOX_BIN" get FAV
	assert_success
	assert_output "sk-12345-secret-api-key"
}

@test "enpass filter: filter by favorite=false excludes favorites" {
	create_test_vault_config 'NOT_FAV = { provider = "enpass", value = "Unique Login/Password", filter = { favorite = "false" } }'

	run "$FNOX_BIN" get NOT_FAV
	assert_success
	assert_output "unique-pass-789"
}

# ─── Filter: Archived ──────────────────────────────────────────────────────

@test "enpass filter: filter by archived=true finds archived items" {
	create_test_vault_config 'OLD = { provider = "enpass", value = "Old Server/Password", filter = { archived = "true" } }'

	run "$FNOX_BIN" get OLD
	assert_success
	assert_output "old-server-pass"
}

@test "enpass filter: archived item username accessible" {
	create_test_vault_config 'OLD_USER = { provider = "enpass", value = "Old Server/Username", filter = { archived = "true" } }'

	run "$FNOX_BIN" get OLD_USER
	assert_success
	assert_output "root"
}

# ─── Filter: Field Value ───────────────────────────────────────────────────

@test "enpass filter: disambiguate by field value (Username)" {
	create_test_vault_config '
DB_ADMIN = { provider = "enpass", value = "Database/Password", filter = { Username = "admin" } }
DB_RO = { provider = "enpass", value = "Database/Password", filter = { Username = "readonly" } }
'

	run "$FNOX_BIN" get DB_ADMIN
	assert_success
	assert_output "db-admin-pass"

	run "$FNOX_BIN" get DB_RO
	assert_success
	assert_output "db-ro-pass"
}

@test "enpass filter: field value filter is case-insensitive" {
	create_test_vault_config 'SECRET = { provider = "enpass", value = "Database/Password", filter = { username = "ADMIN" } }'

	run "$FNOX_BIN" get SECRET
	assert_success
	assert_output "db-admin-pass"
}

@test "enpass filter: field value that doesn't match returns error" {
	create_test_vault_config 'SECRET = { provider = "enpass", value = "Database/Password", filter = { Username = "nonexistent" } }'

	run "$FNOX_BIN" get SECRET
	assert_failure
	assert_output --partial "not found"
}

# ─── Filter: Combined ──────────────────────────────────────────────────────

@test "enpass filter: combined tag + field value" {
	create_test_vault_config '
PROD_ADMIN = { provider = "enpass", value = "Database/Password", filter = { tag = "prod", Username = "admin" } }
'

	run "$FNOX_BIN" get PROD_ADMIN
	assert_success
	assert_output "db-admin-pass"
}

@test "enpass filter: combined tag + category" {
	create_test_vault_config 'LOGIN = { provider = "enpass", value = "GitHub/Password", filter = { tag = "work", category = "login" } }'

	run "$FNOX_BIN" get LOGIN
	assert_success
	assert_output "gh-secret-123"
}

# ─── Ambiguity Tests ───────────────────────────────────────────────────────

@test "enpass: duplicate title without filter uses first match (no error)" {
	create_test_vault_config 'GH = { provider = "enpass", value = "GitHub/Username" }'

	# Without filter, duplicate titles resolve to the first match
	run "$FNOX_BIN" get GH
	assert_success
	# Should get either devuser or personaluser (first match)
	[[ $output == "devuser" || $output == "personaluser" ]]
}

@test "enpass: ambiguous filter still matching multiple items shows error" {
	# Both "Database" items have tag "backend", so filtering by just "backend" is still ambiguous
	create_test_vault_config 'SECRET = { provider = "enpass", value = "Database/Password", filter = { tag = "backend" } }'

	run "$FNOX_BIN" get SECRET
	assert_failure
	assert_output --partial "Multiple items"
}

# ─── Batch & Exec Tests ────────────────────────────────────────────────────

@test "enpass: exec injects multiple secrets into environment" {
	create_test_vault_config '
DB_USER = { provider = "enpass", value = "Unique Login/Username" }
DB_PASS = { provider = "enpass", value = "Unique Login/Password" }
API_KEY = { provider = "enpass", value = "API Key/Note" }
'

	run "$FNOX_BIN" exec -- printenv DB_USER 2>/dev/null
	assert_success
	assert_output --partial "unique@example.com"
}

@test "enpass: exec with filtered secrets" {
	create_test_vault_config '
WORK_GH = { provider = "enpass", value = "GitHub/Password", filter = { tag = "work" } }
PERSONAL_GH = { provider = "enpass", value = "GitHub/Password", filter = { tag = "personal" } }
'

	run bash -c "ENPASS_PASSWORD='$TEST_VAULT_PASSWORD' '$FNOX_BIN' exec -- bash -c 'echo work=\$WORK_GH personal=\$PERSONAL_GH' 2>/dev/null"
	assert_success
	assert_output --partial "work=gh-secret-123"
	assert_output --partial "personal=gh-personal-456"
}

@test "enpass: list shows all configured secrets" {
	create_test_vault_config '
SECRET_A = { provider = "enpass", value = "Unique Login/Username" }
SECRET_B = { provider = "enpass", value = "API Key/Note" }
'

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "SECRET_A"
	assert_output --partial "SECRET_B"
}

@test "enpass: check validates accessible secrets" {
	create_test_vault_config '
GOOD = { provider = "enpass", value = "Unique Login/Password" }
'

	run "$FNOX_BIN" check
	assert_success
}

@test "enpass: check detects inaccessible secrets" {
	create_test_vault_config '
GOOD = { provider = "enpass", value = "Unique Login/Password" }
BAD = { provider = "enpass", value = "Does Not Exist", if_missing = "error" }
'

	run "$FNOX_BIN" check
	assert_failure
	assert_output --partial "BAD"
}

# ─── Real Vault Tests (skipped if ENPASS_PASSWORD not set) ──────────────────

@test "enpass: real vault - get item from user-provided vault" {
	if [[ -z ${ENPASS_PASSWORD:-} ]]; then
		skip "ENPASS_PASSWORD not set - skipping real vault test"
	fi

	local real_vault="$PROJECT_ROOT/test/fixtures/enpass-vault"
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.enpass]
type = "enpass"
vault_path = "$real_vault"

[secrets]
REAL_SECRET = { provider = "enpass", value = "test" }
EOF

	run "$FNOX_BIN" get REAL_SECRET
	assert_success
	assert_output "abc"
}
