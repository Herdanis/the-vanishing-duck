// the-vanishing-duck — core tests for lib.ts
// Run: bun test_scrub.ts

import {
  SECRET_ENV_PATTERN,
  SECRET_REGEXES,
  KV_REGEX,
  FLAG_REGEX,
  FALSE_POSITIVES,
  MAX_SCRUB_SIZE,
  collectEnvSecrets,
  collectEnvFileSecrets,
  collectCustomPatterns,
  isSecretKey,
  isSecretValue,
  scrub,
  logRedactions,
} from "./lib"

import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  statSync,
  existsSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

let passed = 0
let failed = 0

function test(name: string, fn: () => void) {
  try {
    fn()
    passed++
    console.log(`✓ ${name}`)
  } catch (e) {
    failed++
    console.error(`✗ ${name}`)
    console.error(`  ${e instanceof Error ? e.message : e}`)
  }
}

function assert(cond: boolean, msg = "assertion failed") {
  if (!cond) throw new Error(msg)
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "vd-test-"))
}

const redacted = (text: string, secrets = new Map<string, string>(), regexes = SECRET_REGEXES) =>
  scrub(text, secrets, regexes)

// ============================================
// Key-side KV detection
// ============================================

test("prefixed/suffixed keys", () => {
  for (const [input, raw] of [
    ["db_password: hunter2", "hunter2"],
    ["secret_key: abc12345", "abc12345"],
    ["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI", "wJalrXUtnFEMI"],
    ["DB_PASS=x9f2k1", "x9f2k1"],
  ]) {
    const { output } = redacted(input)
    assert(!output.includes(raw), `leaked: ${output}`)
    assert(output.includes("[REDACTED:KV:"), `not redacted: ${output}`)
  }
})

test("camelCase key", () => {
  const { output } = redacted("awsSecretAccessKey: wJalrXUtnFEMI")
  assert(output === "awsSecretAccessKey: [REDACTED:KV:AWS_SECRET_ACCESS_KEY]", output)
})

test("pass / pwd keys", () => {
  const a = redacted("pass: hunter2").output
  assert(a === "pass: [REDACTED:KV:PASS]", a)
  const b = redacted(`pwd="s3cretpw"`).output
  assert(b === `pwd="[REDACTED:KV:PWD]"`, b)
})

test("quotes preserved", () => {
  const { output } = redacted(`{ "api_key": "abcd1234efgh" }`)
  assert(output.includes(`"api_key": "[REDACTED:KV:API_KEY]"`), output)
})

test("CLI flags", () => {
  const a = redacted("--password hunter2").output
  assert(a === "--password [REDACTED:FLAG:PASSWORD]", a)
  const b = redacted("--token=abc12345").output
  assert(b === "--token=[REDACTED:KV:TOKEN]", b)
  assert(FLAG_REGEX.global && KV_REGEX.global)
})

// ============================================
// Code must survive the KV pass
// ============================================

test("code is not redacted", () => {
  const cases = [
    "const token = await getToken()",
    "token = new Token()",
    "const token = getToken()",
    "password: process.env.PASSWORD",
    "if (token === req.token) return true",
    "token: req.headers.token",
    "secret: ${SECRET}",
    "password = null",
    "password: SUPER_SECRET",
    "password: true",
  ]
  for (const input of cases) {
    const { output, redactions } = redacted(input)
    assert(output === input, `changed: ${input} -> ${output}`)
    assert(redactions.length === 0, `redactions on ${input}: ${redactions}`)
  }

  const real = redacted("db_password: hunter2")
  assert(real.output === "db_password: [REDACTED:KV:DB_PASSWORD]", real.output)
})

// ============================================
// Known formats
// ============================================

test("known formats", () => {
  const fixtures: [string, string][] = [
    ["API_KEY", `sk-proj-${"a1B2c3D4e5F6g7H8i9J0k1L2"}`],
    ["STRIPE_KEY", `sk_live_${"abcd1234efgh5678ijkl"}`],
    ["AWS_ACCESS_KEY", "AKIAABCDEFGHIJKLMNOP"],
    ["AWS_SESSION_KEY", "ASIAABCDEFGHIJKLMNOP"],
    ["GITHUB_TOKEN", `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`],
    ["GITHUB_PAT", `github_pat_11ABCDEFG0123456789_abcdefgh`],
    ["GITLAB_TOKEN", `glpat-abcdefghij1234567890`],
    ["NPM_TOKEN", `npm_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`],
    ["PYPI_TOKEN", `pypi-AgEIcHlwaS5vcmc${"abcdefghij"}`],
    ["HF_TOKEN", `hf_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5"}`],
    ["DO_TOKEN", `dop_v1_${"a".repeat(64)}`],
    ["SHOPIFY_TOKEN", `shpat_${"b".repeat(32)}`],
    ["SENDGRID_KEY", `SG.${"a".repeat(22)}.${"b".repeat(43)}`],
    ["SLACK_TOKEN", `xoxb-1234567890-abcdef`],
    ["GOOGLE_OAUTH_SECRET", `GOCSPX-abcdefghijklmnopqrstuvwx`],
    ["GOOGLE_API_KEY", `AIza${"a".repeat(35)}`],
    ["TWILIO_KEY", `SK${"c".repeat(32)}`],
    ["TELEGRAM_BOT_TOKEN", `123456789:AA${"d".repeat(33)}`],
    ["GROQ_KEY", `gsk_${"e".repeat(40)}`],
    ["SUPABASE_KEY", `sbp_${"f".repeat(40)}`],
    ["REPLICATE_TOKEN", `r8_${"g".repeat(20)}`],
    ["AZURE_KEY", `AccountKey=${"A".repeat(40)}`],
    [
      "JWT",
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5NXgL0n3I9PlFUP0THsR8U",
    ],
    [
      "PRIVATE_KEY",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKEfakefakefake\n-----END RSA PRIVATE KEY-----",
    ],
    ["CONN_STRING", "postgres://appuser:fakepassw0rd@db.internal:5432/app"],
  ]
  for (const [label, value] of fixtures) {
    const { output, redactions } = redacted(`value: ${value}`)
    assert(!output.includes(value), `${label} leaked: ${output}`)
    assert(output.includes(`[REDACTED:${label}]`), `${label} not redacted: ${output}`)
    assert(redactions.some((r) => r.startsWith(`${label}#`)), `${label} redactions=${redactions}`)
  }
})

test("Bearer token, not the bare word", () => {
  const tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5NXgL0n3I9PlFUP0THsR8U"
  const withToken = redacted(`Authorization: Bearer ${tok}`)
  assert(!withToken.output.includes(tok), withToken.output)
  assert(withToken.output.startsWith("Authorization: Bearer "), withToken.output)

  const bare = redacted("scheme: Bearer")
  assert(bare.output === "scheme: Bearer", bare.output)
  assert(bare.redactions.length === 0, `redactions=${bare.redactions}`)
})

// ============================================
// Literal map
// ============================================

test("literal map + opt-out", () => {
  const value = "literal_fake_secret_value"
  const secrets = new Map<string, string>([[value, "ENV:FAKE_TOKEN"]])
  const tok = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`
  const text = `env=${value} token=${tok}`

  const full = scrub(text, secrets, SECRET_REGEXES)
  assert(!full.output.includes(value), `literal leaked: ${full.output}`)
  assert(full.output.includes("[REDACTED:ENV:FAKE_TOKEN]"), full.output)

  const noLiterals = scrub(text, secrets, SECRET_REGEXES, { literals: false })
  assert(noLiterals.output.includes(value), `literal pass ran: ${noLiterals.output}`)
  assert(!noLiterals.output.includes(tok), `regex pass skipped: ${noLiterals.output}`)
})

// ============================================
// Guards
// ============================================

test("isSecretKey", () => {
  for (const key of [
    "password",
    "db_password",
    "AWS_SECRET_ACCESS_KEY",
    "awsSecretAccessKey",
    "apiKey",
    "client_secret",
    "session_id",
    "connString",
    "X-Auth-Token",
  ]) {
    assert(isSecretKey(key), `expected secret key: ${key}`)
  }
  for (const key of ["username", "host", "count", "tokenizer", "author", "path"]) {
    assert(!isSecretKey(key), `expected normal key: ${key}`)
  }
})

test("isSecretValue", () => {
  for (const value of ["hunter2", "wJalrXUtnFEMI", "abc12345"]) {
    assert(isSecretValue(value), `expected secret value: ${value}`)
  }
  for (const value of [
    "abc",
    "true",
    "bearer",
    "[REDACTED:KV:X]",
    "getToken()",
    "${SECRET}",
    "a{b}",
    "`x`",
    "path\\to\\file",
    "process.env.TOKEN",
    "req.headers.token",
    "PASSWORD",
    "https://example.com/key",
  ]) {
    assert(!isSecretValue(value), `expected rejected value: ${value}`)
  }
})

test("FALSE_POSITIVES extended", () => {
  for (const v of ["changeme", "xxx", "bearer", "digest", "oauth2", "todo", "unset", "n/a"]) {
    assert(FALSE_POSITIVES.has(v), `missing: ${v}`)
  }
})

test("SECRET_ENV_PATTERN", () => {
  assert(SECRET_ENV_PATTERN.test("DATABASE_PASSWORD"))
  assert(SECRET_ENV_PATTERN.test("GH_TOKEN"))
  assert(SECRET_ENV_PATTERN.test("ACCESS_KEY_ID"))
  assert(!SECRET_ENV_PATTERN.test("HOME"))
  assert(!SECRET_ENV_PATTERN.test("PATH"))
})

test("MAX_SCRUB_SIZE numeric", () => {
  assert(Number.isFinite(MAX_SCRUB_SIZE) && MAX_SCRUB_SIZE > 0, String(MAX_SCRUB_SIZE))
})

// ============================================
// Collection
// ============================================

test("collectEnvFileSecrets", () => {
  const dir = tmp()
  writeFileSync(join(dir, ".env"), 'DATABASE_PASSWORD="pass12345678"\nHOME=/tmp\n')
  const sub = join(dir, "svc")
  mkdirSync(sub)
  writeFileSync(join(sub, ".env.local"), "API_TOKEN=tok_fake_abcdefghijk\n")
  const skipped = join(dir, "node_modules")
  mkdirSync(skipped)
  writeFileSync(join(skipped, ".env"), "DB_PASSWORD=should_not_be_found_here\n")

  const secrets = collectEnvFileSecrets(dir)
  assert(secrets.get("pass12345678") === "ENVFILE:DATABASE_PASSWORD", `${[...secrets.keys()]}`)
  assert(secrets.get("tok_fake_abcdefghijk") === "ENVFILE:API_TOKEN", `${[...secrets.keys()]}`)
  assert(!secrets.has("should_not_be_found_here"), "node_modules scanned")
})

test("collectCustomPatterns literal + regex", () => {
  const dir = tmp()
  const file = join(dir, "secrets.local")
  writeFileSync(
    file,
    "# comment\nmy_custom_fake_value\nregex: \\bvdfake_[a-z0-9]{8}\\b as CMP_TOKEN\n",
  )
  const { literals, regexes } = collectCustomPatterns(file)
  assert(literals.has("my_custom_fake_value"), "literal missing")
  assert(regexes.length === 1, `regexes=${regexes.length}`)
  assert(regexes[0].label === "CUSTOM:CMP_TOKEN", `label=${regexes[0].label}`)
})

test("collectEnvSecrets", () => {
  process.env.VD_TEST_SECRET = "its_a_test_value"
  const s = collectEnvSecrets()
  assert(s.get("its_a_test_value") === "ENV:VD_TEST_SECRET", "not found")
})

// ============================================
// Logging
// ============================================

test("logRedactions: hashed, no preview, mode 600", () => {
  const dir = tmp()
  const { redactions } = scrub("db_password: hunter2", new Map<string, string>(), [])
  assert(redactions.length === 1, `redactions=${redactions}`)
  logRedactions(redactions, "shell", "ses1", dir)

  const path = join(dir, "redaction.log")
  const logged = readFileSync(path, "utf8")
  assert(!logged.includes("hunter2"), "raw value logged")
  assert(!/\w{3}\.\.\.\w{3}/.test(logged), `preview logged: ${logged}`)
  assert(logged.includes(redactions[0]), `tag missing: ${logged}`)
  if (process.platform !== "win32") {
    assert((statSync(path).mode & 0o777) === 0o600, (statSync(path).mode & 0o777).toString(8))
  }
})

test("logRedactions rotates past 1 MB", () => {
  const dir = tmp()
  const path = join(dir, "redaction.log")
  writeFileSync(path, "x".repeat(1024 * 1024 + 10))
  logRedactions(["TEST:X#deadbeef"], "shell", "ses1", dir)
  assert(existsSync(`${path}.1`), "no rotated file")
  assert(!readFileSync(path, "utf8").includes("x".repeat(100)), "log not rotated")
})

// ============================================
// Summary
// ============================================

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
