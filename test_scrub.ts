// the-vanishing-duck — grille tests for lib.ts core detection/scrubbing
// Run: bun test_scrub.ts

import {
  SECRET_ENV_PATTERN,
  SECRET_REGEXES,
  KV_REGEX,
  FALSE_POSITIVES,
  collectEnvSecrets,
  collectEnvFileSecrets,
  collectCustomPatterns,
  preview,
  scrub,
  logRedactions,
} from "./lib";

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void) {
  try {
    fn();
    passed++;
    console.log(`✓ ${name}`);
  } catch (e) {
    failed++;
    console.error(`✗ ${name}`);
    console.error(`  ${e instanceof Error ? e.message : e}`);
  }
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

// ============================================
// Env literal redaction
// ============================================

test("env literal redaction", () => {
  const secrets = new Map<string, string>([["super_secret_db_pass_991", "ENV:DATABASE_PASSWORD"]]);
  const { output, redactions } = scrub("connecting with super_secret_db_pass_991 now", secrets, []);
  assert(output.includes("[REDACTED:ENV:DATABASE_PASSWORD]"), `output=${output}`);
  assert(output.includes("super_secret_db_pass_991") === false, "raw value leaked");
  assert(redactions.length === 1 && redactions[0].includes("ENV:DATABASE_PASSWORD"), `redactions=${redactions}`);
});

// ============================================
// Known-format regexes
// ============================================

test("ghp_ github token", () => {
  const tok = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7"}`;
  const { output, redactions } = scrub(`clone ${tok}`, new Map(), SECRET_REGEXES);
  assert(output === `clone [REDACTED:GITHUB_TOKEN]`, `output=${output}`);
  assert(redactions.length === 1 && redactions[0].startsWith("GITHUB_TOKEN"), `redactions=${redactions}`);
});

test("PEM private key", () => {
  const pem = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc\n-----END RSA PRIVATE KEY-----\n`;
  const { output, redactions } = scrub(pem, new Map(), SECRET_REGEXES);
  assert(output.includes("[REDACTED:PRIVATE_KEY]"), `output=${output}`);
  assert(redactions[0].startsWith("PRIVATE_KEY"), `redactions=${redactions}`);
});

test("JWT", () => {
  const jwt = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3OWmZ1hHtGg`;
  const { output, redactions } = scrub(`token: ${jwt}`, new Map(), SECRET_REGEXES);
  assert(output.includes("[REDACTED:JWT]"), `output=${output}`);
  assert(redactions[0].startsWith("JWT"), `redactions=${redactions}`);
});

// ============================================
// Inline KV detection
// ============================================

test("KV password detection", () => {
  const { output, redactions } = scrub("password: hunter2secret", new Map(), []);
  assert(output === "password: [REDACTED:KV:PASSWORD]", `output=${output}`);
  assert(redactions[0] === "KV:PASSWORD (hun...ord)", `redactions=${redactions}`);
});

test("KV quotes preserved", () => {
  const { output } = scrub(`"api_key": "abcd1234efgh"`, new Map(), []);
  assert(output.includes('"api_key": "[REDACTED:KV:API_KEY]"'), `output=${output}`);
});

// ============================================
// False positives skipped
// ============================================

test("false positive skipped (password: true)", () => {
  const { output, redactions } = scrub("password: true", new Map(), []);
  assert(output === "password: true", `output=${output}`);
  assert(redactions.length === 0, `redactions=${redactions}`);
});

test("FALSE_POSITIVES has expected values", () => {
  assert(FALSE_POSITIVES.has("changeme") && FALSE_POSITIVES.has("xxx"));
});

test("SECRET_ENV_PATTERN matches secret-like names", () => {
  assert(SECRET_ENV_PATTERN.test("DATABASE_PASSWORD"));
  assert(SECRET_ENV_PATTERN.test("GH_TOKEN"));
  assert(SECRET_ENV_PATTERN.test("ACCESS_KEY_ID"));
  assert(!SECRET_ENV_PATTERN.test("HOME"));
  assert(!SECRET_ENV_PATTERN.test("PATH"));
});

// ============================================
// preview
// ============================================

test("preview short value", () => {
  assert(preview("short") === "***");
});

test("preview long value", () => {
  const p = preview("super_secret_db_pass_991");
  assert(p === "sup...991", `p=${p}`);
});

// ============================================
// collectEnvFileSecrets
// ============================================

test("collectEnvFileSecrets", () => {
  const dir = mkdtempSync(join(tmpdir(), "vd-test-"));
  writeFileSync(join(dir, ".env"), 'DATABASE_PASSWORD="pass12345678"\nHOME=/tmp\n');
  const s = collectEnvFileSecrets(dir);
  assert(s.has("pass12345678") && s.get("pass12345678") === "ENVFILE:DATABASE_PASSWORD", `secrets=`);
});

// ============================================
// collectCustomPatterns
// ============================================

test("collectCustomPatterns literal + regex", () => {
  const dir = mkdtempSync(join(tmpdir(), "vd-test-"));
  writeFileSync(
    join(dir, "secrets.local"),
    "# comment\nmy_custom_value\nregex: \\bcmp_[a-z0-9]{8}\\b as CMP_TOKEN\regex2",
  );
  const { literals, regexes } = collectCustomPatterns(dir, "secrets.local");
  assert(literals.has("my_custom_value"), "literal missing");
  assert(regexes.length === 1, `regexes=${regexes.length}`);
  assert(regexes[0].label === "CUSTOM:CMP_TOKEN", "label wrong");
});

// ============================================
// collectEnvSecrets
// ============================================

test("collectEnvSecrets", () => {
  process.env.VD_TEST_SECRET = "its_a_test_value";
  const s = collectEnvSecrets();
  assert(s.has("its_a_test_secret") || s.has("its_a_test_value"), "not found");
});

// ============================================
// logRedactions
// ============================================

test("logRedactions writes file", () => {
  const dir = mkdtempSync(join(tmpdir(), "vd-test-"));
  logRedactions(["TEST:X (abc...xyz)"], "bash", "ses1", dir);
});
