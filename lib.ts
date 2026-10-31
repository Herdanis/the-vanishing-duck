// the-vanishing-duck — detection/scrubbing core
//
// Harness-agnostic. Used by plugin.ts (OpenCode) and extension.ts (pi/omp).
// Same behavior as the original inline core in plugin.ts.

import { readFileSync, existsSync, appendFileSync, mkdirSync } from "node:fs"
import { join } from "node:path"
import { homedir } from "node:os"

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

// Known secret format regexes.
export const SECRET_REGEXES: { re: RegExp; label: string }[] = [
  { re: /sk-[A-Za-z0-9]{20,}/g, label: "API_KEY" },
  { re: /AKIA[0-9A-Z]{16}/g, label: "AWS_ACCESS_KEY" },
  { re: /ASIA[0-9A-Z]{16}/g, label: "AWS_SESSION_KEY" },
  { re: /gh[ops]_[A-Za-z0-9]{36}/g, label: "GITHUB_TOKEN" },
  { re: /xox[bpras]-[A-Za-z0-9-]+/g, label: "SLACK_TOKEN" },
  { re: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, label: "JWT" },
  {
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----/g,
    label: "PRIVATE_KEY",
  },
  {
    re: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
    label: "CONN_STRING",
  },
  { re: /AIza[0-9A-Za-z_-]{35}/g, label: "GOOGLE_API_KEY" },
]

// Tools whose output we scrub.
export const SCRUB_TOOLS = new Set(["bash", "read", "grep", "glob", "webfetch"])

// .env files to scan for secrets (relative to project root).
export const ENV_FILES = [".env", ".env.local", ".env.production", ".env.development", ".env.staging"]

// Inline key-value detection: finds password: xxx, secret=xxx, etc.
// Catches secrets in config files, YAML, JSON, .env output — even
// values not pre-collected. Group 1=key, 2=sep, 3=dq-val, 4=sq-val, 5=bare-val.
export const KV_REGEX =
  /\b(password|passwd|secret|token|api_?key|credential|private_?key|access_?key|auth_?token)\b(\s*[:=]\s*)(?:"([^"]{4,})"|'([^']{4,})'|([^\s"'[{,}]{4,}))/gi

// Values that look like secrets but aren't — skip to avoid false positives.
export const FALSE_POSITIVES = new Set([
  "true", "false", "null", "none", "undefined", "nil", "",
  "changeme", "password", "secret", "example", "your_password",
  "your_secret", "your_token", "xxx", "test", "demo", "placeholder",
  "redacted", "hidden", "string", "value", "config",
])

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

function collectConfigSecrets(): Map<string, string> {
  const secrets = new Map<string, string>()
  const configDir = join(homedir(), ".config", "opencode")
  const candidates = ["opencode.jsonc", "opencode.json"]
  for (const name of candidates) {
    const configPath = join(configDir, name)
    if (!existsSync(configPath)) continue
    try {
      const text = readFileSync(configPath, "utf8")
      const re = /"apiKey"\s*:\s*"([^"]+)"/g
      let m: RegExpExecArray | null
      while ((m = re.exec(text)) !== null) {
        if (m[1].length > 8) secrets.set(m[1], "CONFIG:apiKey")
      }
    } catch {}
  }
  return secrets
}

function collectEnvFileSecrets(directory: string): Map<string, string> {
  const secrets = new Map<string, string>()
  for (const f of ENV_FILES) {
    const p = join(directory, f)
    if (!existsSync(p)) continue
    try {
      const text = readFileSync(p, "utf8")
export function collectCustomPatterns(): { literals: Map<string, string>; regexes: { re: RegExp; label: string }[] } {
  const literals = new Map<string, string>()
  const regexes: { re: RegExp; label: string }[] = []
  if (!existsSync(CUSTOM_PATTERNS_PATH)) return { literals, regexes }
  try {
    const text = readFileSync(CUSTOM_PATTERNS_PATH, "utf8")
    for (const line of text.split("\n")) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#")) continue
      if (trimmed.startsWith("regex:")) {
        const rest = trimmed.slice(6).trim()
        const [pattern, label] = rest.split(/\s+as\s+/)
        try {
          regexes.push({ re: new RegExp(pattern, "g"), label: label ? `CUSTOM:${label}` : "CUSTOM" })
        } catch {}
      } else {
        if (trimmed.length > 3 && !FALSE_POSITIVES.has(trimmed.toLowerCase())) {
          literals.set(trimmed, "CUSTOM")
        }
      }
    }
  } catch {}
  return { literals, regexes }
}

// ============================================
// Scrubbing
// ============================================

export function preview(val: string): string {
  if (val.length <= 8) return "***"
  return `${val.slice(0, 3)}...${val.slice(-3)}`
}

export function scrub(
  text: string,
  secrets: Map<string, string>,
  regexes: { re: RegExp; label: string }[],
): { output: string; redactions: string[] } {
  if (!text) return { output: text, redactions: [] }

  let result = text
  const redactions: string[] = []

  // Replace literal secret values (longest first to avoid partial matches).
  const sorted = [...secrets.entries()].sort((a, b) => b[0].length - a[0].length)
  for (const [value, label] of sorted) {
    if (result.includes(value)) {
      redactions.push(`${label} (${preview(value)})`)
      result = result.split(value).join(`[REDACTED:${label}]`)
    }
  }

  // Replace regex patterns.
  for (const { re, label } of regexes) {
    const matches = result.match(re)
    if (matches) {
      for (const m of matches) {
        redactions.push(`${label} (${preview(m)})`)
      }
      re.lastIndex = 0
      result = result.replace(re, `[REDACTED:${label}]`)
    }
  }

  // Inline KV detection: finds password: xxx, secret=xxx, etc.
  // Catches secrets in config/YAML/JSON output even if not pre-collected.
  result = result.replace(
    KV_REGEX,
    (match, key: string, sep: string, dq?: string, sq?: string, bare?: string) => {
      const val = dq || sq || bare
      if (!val || FALSE_POSITIVES.has(val.toLowerCase())) return match
      if (val.startsWith("[REDACTED:")) return match
      redactions.push(`KV:${key.toUpperCase()} (${preview(val)})`)
      const quote = dq ? '"' : sq ? "'" : ""
      return `${key}${sep}${quote}[REDACTED:KV:${key.toUpperCase()}]${quote}`
    },
  )

  return { output: result, redactions }
}

// ============================================
// Local logging
// ============================================

export function logRedactions(redactions: string[], tool: string, sessionId: string) {
  try {
    mkdirSync(DATA_DIR, { recursive: true })
    const ts = new Date().toISOString()
    const lines = redactions
      .map((r) => `[${ts}] session=${sessionId} tool=${tool} redacted=${r}`)
      .join("\n")
    appendFileSync(LOG_PATH, lines + "\n", { encoding: "utf8" })
  } catch {}
}
