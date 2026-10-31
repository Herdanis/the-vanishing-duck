// the-vanishing-duck — detection/scrubbing core
//
// Harness-agnostic. Used by plugin.ts (OpenCode).

import {
  readFileSync,
  existsSync,
  appendFileSync,
  mkdirSync,
  readdirSync,
  statSync,
  renameSync,
  chmodSync,
} from "node:fs"
import { join } from "node:path"
import { homedir } from "node:os"
import { createHash } from "node:crypto"

// ============================================
// Config
// ============================================

export const DATA_DIR = process.env.VANISHING_DUCK_DIR
  ?? join(homedir(), ".config", "the-vanishing-duck")
export const LOG_PATH = join(DATA_DIR, "redaction.log")
export const CUSTOM_PATTERNS_PATH = join(DATA_DIR, "secrets.local")
export const MAX_SCRUB_SIZE = parseInt(process.env.VANISHING_DUCK_MAX_SIZE ?? "512000", 10)

// Env var names that typically hold secrets.
export const SECRET_ENV_PATTERN =
  /^(.*(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH).*)$/i

// Known secret formats.
export const SECRET_REGEXES: { re: RegExp; label: string }[] = [
  { re: /sk-[A-Za-z0-9_-]{20,}/g, label: "API_KEY" },
  { re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g, label: "STRIPE_KEY" },
  { re: /AKIA[0-9A-Z]{16}/g, label: "AWS_ACCESS_KEY" },
  { re: /ASIA[0-9A-Z]{16}/g, label: "AWS_SESSION_KEY" },
  { re: /\bgh[opusr]_[A-Za-z0-9]{36}\b/g, label: "GITHUB_TOKEN" },
  { re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, label: "GITHUB_PAT" },
  { re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, label: "GITLAB_TOKEN" },
  { re: /\bnpm_[A-Za-z0-9]{36}\b/g, label: "NPM_TOKEN" },
  { re: /\bpypi-AgE[A-Za-z0-9_-]{20,}\b/g, label: "PYPI_TOKEN" },
  { re: /\bhf_[A-Za-z0-9]{30,}\b/g, label: "HF_TOKEN" },
  { re: /\bdop_v1_[a-f0-9]{64}\b/g, label: "DO_TOKEN" },
  { re: /\bshpat_[a-f0-9]{32}\b/g, label: "SHOPIFY_TOKEN" },
  { re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, label: "SENDGRID_KEY" },
  { re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, label: "SLACK_TOKEN" },
  { re: /\bGOCSPX-[A-Za-z0-9_-]{20,}/g, label: "GOOGLE_OAUTH_SECRET" },
  { re: /\bAIza[0-9A-Za-z_-]{35}/g, label: "GOOGLE_API_KEY" },
  { re: /\bSK[0-9a-f]{32}\b/g, label: "TWILIO_KEY" },
  { re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, label: "TELEGRAM_BOT_TOKEN" },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, label: "JWT" },
  { re: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi, label: "BEARER_TOKEN" },
  { re: /\bgsk_[A-Za-z0-9]{40,}\b/g, label: "GROQ_KEY" },
  { re: /\bsbp_[a-f0-9]{40}\b/g, label: "SUPABASE_KEY" },
  { re: /\br8_[A-Za-z0-9]{20,}\b/g, label: "REPLICATE_TOKEN" },
  { re: /\bAccountKey=[A-Za-z0-9+/=]{40,}/g, label: "AZURE_KEY" },
  {
    re: /-----BEGIN (?:[A-Z0-9]+ )*(?:PRIVATE KEY|BLOCK)(?: BLOCK)?[\s\S]*?-----END (?:[A-Z0-9]+ )*(?:PRIVATE KEY|BLOCK)(?: BLOCK)?-----/g,
    label: "PRIVATE_KEY",
  },
  {
    re: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mssql|clickhouse|ftp|ftps|smtp):\/\/[^:\s/@]+:[^@\s]+@[^\s"']+/g,
    label: "CONN_STRING",
  },
]

// Tools to leave alone (plugin denylist).
export const SKIP_TOOLS = new Set(["todowrite", "todoread", "skill"])

// .env files to scan.
export const ENV_FILES = [".env", ".env.local", ".env.production", ".env.development", ".env.staging"]

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".venv", "vendor"])

// Inline key/value: group 1=key quote, 2=key, 3=dq, 4=sq, 5=bare. Guarded by isSecretKey.
export const KV_REGEX =
  /("?)([A-Za-z_$][\w.$-]*)\1\s*[:=]\s*(?:"([^"\n]{3,})"|'([^'\n]{3,})'|([^\s"'`\[{,}]{3,}))/g

// CLI flags carrying secrets: group 1=flag+sep, 2=dq, 3=sq, 4=bare.
export const FLAG_REGEX =
  /(--(?:password|passwd|pass|pwd|passphrase|token|api-?key|apikey|secret|client-secret|auth-token)(?:=|\s+))(?:"([^"\n]{3,})"|'([^'\n]{3,})'|([^\s"'`]{3,}))/gi

// Values that look like secrets but aren't.
export const FALSE_POSITIVES = new Set([
  "true", "false", "null", "none", "undefined", "nil", "",
  "changeme", "password", "secret", "example", "your_password",
  "your_secret", "your_token", "xxx", "test", "demo", "placeholder",
  "redacted", "hidden", "string", "value", "config",
  "bearer", "basic", "digest", "oauth2", "required", "optional",
  "enabled", "disabled", "default", "empty", "unknown", "inherit",
  "n/a", "na", "todo", "tbd", "unset",
])

const CODE_WORDS = new Set([
  "await", "async", "function", "const", "let", "var", "return", "new",
  "this", "class", "import", "export", "from", "yield", "typeof",
  "instanceof", "void", "delete", "super", "static", "public", "private",
  "protected", "readonly", "interface", "enum", "def", "lambda", "and",
  "or", "not", "if", "else", "elif", "for", "while", "try", "catch",
  "finally", "raise", "with", "as", "in", "is", "global", "nonlocal",
  "print", "echo", "cat", "cd", "sudo", "npm", "bun", "node", "python",
  "git", "true", "false", "null", "undefined", "nan",
])

const KEY_WORDS = new Set([
  "password", "passwd", "pass", "pwd", "passphrase", "passcode", "pin",
  "otp", "secret", "token", "apikey", "credential", "credentials",
  "privatekey", "accesskey", "secretkey", "clientsecret", "auth",
  "authorization", "bearer", "cookie", "dsn",
])

const KEY_PAIRS: [string, string][] = [
  ["api", "key"], ["secret", "key"], ["private", "key"], ["access", "key"],
  ["signing", "key"], ["encryption", "key"], ["master", "key"],
  ["client", "secret"], ["refresh", "token"], ["auth", "token"],
  ["session", "id"], ["conn", "string"], ["connection", "string"],
]

// ============================================
// Guards
// ============================================

function keyParts(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((p) => p.toLowerCase())
}

export function isSecretKey(key: string): boolean {
  const parts = keyParts(key)
  if (parts.some((p) => KEY_WORDS.has(p))) return true
  return KEY_PAIRS.some(([a, b]) => parts.some((p, i) => p === a && parts[i + 1] === b))
}

export function isSecretValue(value: string): boolean {
  if (!value || value.length < 4) return false
  if (FALSE_POSITIVES.has(value.toLowerCase())) return false
  if (CODE_WORDS.has(value.toLowerCase())) return false
  if (value.startsWith("[REDACTED:")) return false
  if (/[(){}<>`$\\]/.test(value)) return false
  if (/^https?:\/\//i.test(value)) return false
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value)) return false
  if (/^[A-Z][A-Z0-9_]*$/.test(value)) return false
  return true
}

// ============================================
// Secret collection
// ============================================

export function collectEnvSecrets(): Map<string, string> {
  const secrets = new Map<string, string>()
  for (const [name, value] of Object.entries(process.env)) {
    if (SECRET_ENV_PATTERN.test(name) && value && value.length > 8) {
      secrets.set(value, `ENV:${name}`)
    }
  }
  return secrets
}

export function collectConfigSecrets(): Map<string, string> {
  const secrets = new Map<string, string>()
  const configDir = join(homedir(), ".config", "opencode")
  for (const name of ["opencode.jsonc", "opencode.json"]) {
    const configPath = join(configDir, name)
    if (!existsSync(configPath)) continue
    try {
      const text = readFileSync(configPath, "utf8")
      const re = /"([A-Za-z_$][\w.$-]*)"\s*:\s*"([^"\n]{8,})"/g
      let m: RegExpExecArray | null
      while ((m = re.exec(text)) !== null) {
        if (isSecretKey(m[1])) secrets.set(m[2], `CONFIG:${m[1]}`)
      }
    } catch {}
  }
  return secrets
}

function addEnvFile(path: string, secrets: Map<string, string>) {
  let text: string
  try {
    text = readFileSync(path, "utf8")
  } catch {
    return
  }
  for (const line of text.split("\n")) {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/)
    if (!m) continue
    const [, name, rawVal] = m
    if (!SECRET_ENV_PATTERN.test(name)) continue
    const val = rawVal.trim().replace(/^["']|["']$/g, "").split(/\s+#/)[0].trim()
    if (val.length > 8 && !FALSE_POSITIVES.has(val.toLowerCase())) {
      secrets.set(val, `ENVFILE:${name}`)
    }
  }
}

export function collectEnvFileSecrets(directory: string): Map<string, string> {
  const secrets = new Map<string, string>()
  const paths = new Set<string>()

  for (const f of ENV_FILES) paths.add(join(directory, f))

  try {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (!entry.isDirectory() || SKIP_DIRS.has(entry.name)) continue
      try {
        for (const f of readdirSync(join(directory, entry.name))) {
          if (f.startsWith(".env")) paths.add(join(directory, entry.name, f))
        }
      } catch {}
    }
  } catch {}

  for (const p of paths) {
    if (existsSync(p)) addEnvFile(p, secrets)
  }
  return secrets
}

export function collectCustomPatterns(
  path: string = CUSTOM_PATTERNS_PATH,
): { literals: Map<string, string>; regexes: { re: RegExp; label: string }[] } {
  const literals = new Map<string, string>()
  const regexes: { re: RegExp; label: string }[] = []
  if (!existsSync(path)) return { literals, regexes }
  try {
    const text = readFileSync(path, "utf8")
    for (const line of text.split("\n")) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#")) continue
      if (trimmed.startsWith("regex:")) {
        const rest = trimmed.slice(6).trim()
        const [pattern, label] = rest.split(/\s+as\s+/)
        try {
          regexes.push({ re: new RegExp(pattern, "g"), label: label ? `CUSTOM:${label}` : "CUSTOM" })
        } catch {}
      } else if (trimmed.length > 3 && !FALSE_POSITIVES.has(trimmed.toLowerCase())) {
        literals.set(trimmed, "CUSTOM")
      }
    }
  } catch {}
  return { literals, regexes }
}

// ============================================
// Scrubbing
// ============================================

function tag(label: string, value: string): string {
  return `${label}#${createHash("sha256").update(value).digest("hex").slice(0, 8)}`
}

function kvKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toUpperCase()
    .replace(/[^A-Z0-9_]+/g, "_")
}

export function scrub(
  text: string,
  secrets: Map<string, string>,
  regexes: { re: RegExp; label: string }[],
  opts?: { literals?: boolean },
): { output: string; redactions: string[] } {
  if (!text) return { output: text, redactions: [] }

  let result = text
  const redactions: string[] = []

  // Literal values, longest first to avoid partial matches.
  if (opts?.literals !== false) {
    const sorted = [...secrets.entries()].sort((a, b) => b[0].length - a[0].length)
    for (const [value, label] of sorted) {
      if (!result.includes(value)) continue
      redactions.push(tag(label, value))
      result = result.split(value).join(`[REDACTED:${label}]`)
    }
  }

  for (const { re, label } of regexes) {
    re.lastIndex = 0
    const matches = result.match(re)
    if (!matches) continue
    for (const m of matches) redactions.push(tag(label, m))
    re.lastIndex = 0
    result = result.replace(re, `[REDACTED:${label}]`)
  }

  result = result.replace(
    KV_REGEX,
    (match: string, q: string, key: string, dq?: string, sq?: string, bare?: string) => {
      const val = dq ?? sq ?? bare
      if (!val || !isSecretKey(key) || !isSecretValue(val)) return match
      const raw = dq !== undefined ? `"${dq}"` : sq !== undefined ? `'${sq}'` : bare!
      const head = `${q}${key}${q}`
      const sep = match.slice(head.length, match.length - raw.length)
      const quote = dq !== undefined ? '"' : sq !== undefined ? "'" : ""
      const label = kvKey(key)
      redactions.push(tag(`KV:${label}`, val))
      return `${head}${sep}${quote}[REDACTED:KV:${label}]${quote}`
    },
  )

  result = result.replace(FLAG_REGEX, (match: string, flag: string, dq?: string, sq?: string, bare?: string) => {
    const val = dq ?? sq ?? bare
    if (!val || !isSecretValue(val)) return match
    const quote = dq !== undefined ? '"' : sq !== undefined ? "'" : ""
    const name = flag.replace(/^--/, "").replace(/[=\s]+$/, "").toUpperCase().replace(/[^A-Z0-9]+/g, "_")
    redactions.push(tag(`FLAG:${name}`, val))
    return `${flag}${quote}[REDACTED:FLAG:${name}]${quote}`
  })

  return { output: result, redactions }
}

// ============================================
// Local logging
// ============================================

const MAX_LOG_SIZE = 1024 * 1024

export function logRedactions(
  redactions: string[],
  tool: string,
  sessionId: string,
  dir: string = DATA_DIR,
): void {
  try {
    mkdirSync(dir, { recursive: true })
    const logPath = join(dir, "redaction.log")
    if (existsSync(logPath) && statSync(logPath).size > MAX_LOG_SIZE) {
      renameSync(logPath, `${logPath}.1`)
    }
    const ts = new Date().toISOString()
    const lines = redactions
      .map((r) => `[${ts}] session=${sessionId} tool=${tool} redacted=${r}`)
      .join("\n")
    appendFileSync(logPath, lines + "\n", { encoding: "utf8" })
    chmodSync(logPath, 0o600)
  } catch {}
}
