# the-vanishing-duck

OpenCode plugin — runtime secret scrubbing for AI coding agents.

Secrets stay local. The model sees `[REDACTED:TYPE]` placeholders only.

## What it does

Intercepts tool output (bash, read, grep, glob, webfetch) and user chat messages, redacting sensitive values **before** they reach the AI model. Runs as code — zero context cost, AI never sees instructions, cannot be bypassed.

```
AI runs:  echo $DATABASE_PASSWORD
Output:   super_secret_123
Model sees: [REDACTED:ENV:DATABASE_PASSWORD]
```

## Six detection strategies

| # | Strategy | What it catches |
|---|----------|----------------|
| 1 | Env vars | `DATABASE_PASSWORD=pass123` in `process.env` |
| 2 | Config file | `apiKey` values in `opencode.json` / `opencode.jsonc` |
| 3 | `.env` files | `DB_PASSWORD=mypass123` in project `.env` files |
| 4 | Custom patterns | Literal values + regex from `secrets.local` file |
| 5 | Known formats | AWS `AKIA*`, GitHub `ghp_*`, OpenAI `sk-*`, JWT, PEM keys, DB conn strings, Google `AIza*`, Slack `xox*` |
| 6 | Inline KV detection | `password: xxx`, `secret=xxx` in any output — catches secrets with no format pattern |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Herdanis/the-vanishing-duck/main/install.sh | bash
```

Or clone + run:

```bash
git clone https://github.com/Herdanis/the-vanishing-duck.git
bash the-vanishing-duck/install.sh
```

The script:
1. Clones repo to `~/.config/opencode/plugins/the-vanishing-duck/`
2. Registers plugin in `opencode.jsonc`
3. Creates data dir at `~/.config/the-vanishing-duck/`
4. Scans env vars, `.env` files, config apiKey values
5. Lets you add custom secret values + regex patterns interactively
6. Tests scrubbing
7. Shows summary

Restart OpenCode after installing.

## Custom patterns

Create `~/.config/the-vanishing-duck/secrets.local`:

```
# Literal values — redacted everywhere they appear
my_database_password
internal-api-key-12345

# Regex patterns — custom format detection
regex: \bcompany_[a-z0-9]{20}\b as COMPANY_TOKEN
regex: \bint_[a-z0-9]{16}\b as INTERNAL_ID
```

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `VANISHING_DUCK_DIR` | `~/.config/the-vanishing-duck` | Data directory (log, custom patterns) |
| `VANISHING_DUCK_MAX_SIZE` | `512000` | Max output size to scrub (bytes). Larger outputs skipped for perf |

## How it works

### Tool output scrubbing

Hooks `tool.execute.after` — fires after bash/read/grep/glob/webfetch runs, before output enters model context.

```
bash runs `cat .env`
  → output: "DB_PASSWORD=mypass123"
  → plugin intercepts
  → replaces: "DB_PASSWORD=[REDACTED:KV:PASSWORD]"
  → model receives: redacted version
  → local log: what was scrubbed (you see it, model doesn't)
```

### Chat message scrubbing

Hooks `chat.message` — fires when user sends a message, before model sees it.

```
User types: "my API key is sk-1234567890abcdef"
  → plugin intercepts
  → replaces: "my API key is [REDACTED:API_KEY]"
  → model receives: redacted version
```

### Inline KV detection

Catches secrets in config files, YAML, JSON, `.env` output — even values not pre-collected:

```yaml
database:
  password: mySecretPass123      →  password: [REDACTED:KV:PASSWORD]
  secret_key: abc123def456       →  secret_key: [REDACTED:KV:SECRET_KEY]
```

```json
{"api_key": "sk-real-key-here"}  →  {"api_key": "[REDACTED:KV:API_KEY]"}
```

Matches keys containing: `password`, `secret`, `token`, `api_key`, `credential`, `private_key`, `access_key`, `auth_token`. Skips false positives (`true`, `null`, `changeme`, `test`, etc.).

## Redaction log

All redactions logged locally at `~/.config/the-vanishing-duck/redaction.log`:

```
[2026-09-14T10:30:00Z] session=abc123 tool=bash redacted=ENV:DATABASE_PASSWORD (sup...123)
[2026-09-14T10:31:00Z] session=abc123 tool=chat.message redacted=KV:API_KEY (sk-1...def)
```

Preview shows first 3 + last 3 chars only. Full secret never logged.

## Limitations

- Binary/compiled files — output is binary garbage, regex won't match
- Very short passwords (<4 chars) — KV regex requires value ≥4 chars to avoid false positives
- Base64/encrypted secrets — no readable pattern to match
- Secrets in images/PDFs — not scanned

No tool catches 100%. This covers: env vars, `.env` files, config files, known formats, inline KV pairs, and custom patterns.

## License

MIT
