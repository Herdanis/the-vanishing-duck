// the-vanishing-duck — runtime secret scrubbing for OpenCode
//
// Intercepts tool output (bash, read, grep, glob, webfetch) and user chat
// messages, redacting sensitive values before they reach the AI model.
// Secrets stay local; model sees [REDACTED:TYPE] placeholders only.
//
// Six detection strategies:
//   1. Env vars with secret-like names → literal value replaced
//   2. opencode.json/jsonc apiKey values → literal value replaced
//   3. .env files in project root → literal values replaced
//   4. Custom literal values from secrets.local → literal replaced
//   5. Known secret regex formats (AWS, GitHub, OpenAI, JWT, PEM, etc.)
//   6. Inline key-value detection (password: xxx, secret=xxx in any output)
//
// Zero context cost — runs as code, AI never sees instructions.
// Configurable via env vars: VANISHING_DUCK_DIR, VANISHING_DUCK_MAX_SIZE

import { readFileSync, existsSync, appendFileSync, mkdirSync } from "node:fs"
import { join } from "node:path"
import { homedir } from "node:os"

// ============================================
// Config
// ============================================

const DATA_DIR = process.env.VANISHING_DUCK_DIR
  ?? join(homedir(), ".config", "the-vanishing-duck")
const LOG_PATH = join(DATA_DIR, "redaction.log")
const CUSTOM_PATTERNS_PATH = join(DATA_DIR, "secrets.local")
const MAX_SCRUB_SIZE = parseInt(process.env.VANISHING_DUCK_MAX_SIZE ?? "512000", 10)

// Env var names that typically hold secrets.
const SECRET_ENV_PATTERN =
  /^(.*(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH).*)$/i

// Known secret format regexes.
const SECRET_REGEXES: { re: RegExp; label: string }[] = [
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
const SCRUB_TOOLS = new Set(["shell", "read", "grep", "glob", "webfetch"])

// .env files to scan for secrets (relative to project root).
const ENV_FILES = [".env", ".env.local", ".env.production", ".env.development", ".env.staging"]

// Inline key-value detection: finds password: xxx, secret=xxx, etc.
// Catches secrets in config files, YAML, JSON, .env output — even
// values not pre-collected. Group 1=key, 2=sep, 3=dq-val, 4=sq-val, 5=bare-val.
const KV_REGEX =
  /\b(password|passwd|secret|token|api_?key|credential|private_?key|access_?key|auth_?token)\b(\s*[:=]\s*)(?:"([^"]{4,})"|'([^']{4,})'|([^\s"'[{,}]{4,}))/gi

// Values that look like secrets but aren't — skip to avoid false positives.
const FALSE_POSITIVES = new Set([
  "true", "false", "null", "none", "undefined", "nil", "",
  "changeme", "password", "secret", "example", "your_password",
  "your_secret", "your_token", "xxx", "test", "demo", "placeholder",
  "redacted", "hidden", "string", "value", "config",
])

// ============================================
// Secret collection
// ============================================

function collectEnvSecrets(): Map<string, string> {
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
      for (const line of text.split("\n")) {
        const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/)
        if (!m) continue
        const [, name, rawVal] = m
        if (!SECRET_ENV_PATTERN.test(name)) continue
        let val = rawVal.trim().replace(/^["']|["']$/g, "").split(/\s+#/)[0].trim()
        if (val.length > 8 && !FALSE_POSITIVES.has(val.toLowerCase())) {
          secrets.set(val, `ENVFILE:${name}`)
        }
      }
    } catch {}
  }
  return secrets
}

function collectCustomPatterns(): { literals: Map<string, string>; regexes: { re: RegExp; label: string }[] } {
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

function preview(val: string): string {
  if (val.length <= 8) return "***"
  return `${val.slice(0, 3)}...${val.slice(-3)}`
}

function scrub(
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

function logRedactions(redactions: string[], tool: string, sessionId: string) {
  try {
    mkdirSync(DATA_DIR, { recursive: true })
    const ts = new Date().toISOString()
    const lines = redactions
      .map((r) => `[${ts}] session=${sessionId} tool=${tool} redacted=${r}`)
      .join("\n")
    appendFileSync(LOG_PATH, lines + "\n", { encoding: "utf8" })
  } catch {}
}

// ============================================
// Plugin
// ============================================

type ToolHookEvent = {
  tool: string
  sessionID: string
  status: "completed" | "error"
  result?: {
    content?: { type: string; text?: string }[]
    output?: { output?: string }
  }
}

type PromptHookEvent = {
  sessionID: string
  prompt: { text: string }
}

type PluginContext = {
  location: { directory: string }
  tool: { hook(name: "execute.after", cb: (event: ToolHookEvent) => void): Promise<unknown> }
  session: { hook(name: "prompt", cb: (event: PromptHookEvent) => void): Promise<unknown> }
}

function notice(count: number): string {
  return (
    `\n\n[the-vanishing-duck: ${count} redaction(s). ` +
    `Sensitive values replaced with [REDACTED:*]. ` +
    `Local log: ${LOG_PATH}]`
  )
}

export default {
  id: "the-vanishing-duck",
  async setup(ctx: PluginContext) {
    const secrets = new Map<string, string>()
    for (const [v, l] of collectEnvSecrets()) secrets.set(v, l)
    for (const [v, l] of collectConfigSecrets()) secrets.set(v, l)
    for (const [v, l] of collectEnvFileSecrets(ctx.location.directory)) secrets.set(v, l)

    const custom = collectCustomPatterns()
    for (const [v, l] of custom.literals) secrets.set(v, l)
    const allRegexes = [...SECRET_REGEXES, ...custom.regexes]

    // ── Tool output scrubbing ──────────────────────────────────────
    // Shell/read/grep/glob/webfetch content → scrubbed before model
    // sees it. Secrets stay local, model sees [REDACTED:*].
    await ctx.tool.hook("execute.after", (event) => {
      if (event.status !== "completed" || !SCRUB_TOOLS.has(event.tool)) return
      const result = event.result
      if (!result) return

      const redactions: string[] = []
      let lastText: { type: string; text?: string } | undefined

      for (const part of result.content ?? []) {
        if (part.type !== "text" || !part.text) continue
        if (part.text.length > MAX_SCRUB_SIZE) continue
        const scrubbed = scrub(part.text, secrets, allRegexes)
        if (scrubbed.redactions.length === 0) continue
        part.text = scrubbed.output
        lastText = part
        redactions.push(...scrubbed.redactions)
      }

      const raw = result.output?.output
      if (raw && raw.length <= MAX_SCRUB_SIZE) {
        const scrubbed = scrub(raw, secrets, allRegexes)
        if (scrubbed.redactions.length > 0 && result.output) {
          result.output.output = scrubbed.output
          redactions.push(...scrubbed.redactions)
        }
      }

      if (redactions.length === 0) return
      if (lastText?.text !== undefined) lastText.text += notice(redactions.length)
      logRedactions(redactions, event.tool, event.sessionID ?? "unknown")
    })

    // ── Chat message scrubbing ────────────────────────────────────
    // User-typed messages → scrubbed before model sees them. If user
    // pastes a secret into chat (intentionally or not), it gets
    // redacted. The model never sees the raw value.
    await ctx.session.hook("prompt", (event) => {
      const text = event.prompt?.text
      if (!text || text.length > MAX_SCRUB_SIZE) return

      const scrubbed = scrub(text, secrets, allRegexes)
      if (scrubbed.redactions.length === 0) return

      event.prompt.text = scrubbed.output
      logRedactions(scrubbed.redactions, "session.prompt", event.sessionID ?? "unknown")
    })
  },
}
