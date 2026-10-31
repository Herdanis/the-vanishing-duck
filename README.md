# the-vanishing-duck

OpenCode plugin — runtime secret scrubbing for AI coding agents.

Secrets stay local. The model sees `[REDACTED:TYPE]` placeholders only.

## What it does

Intercepts tool output and user chat messages, redacting sensitive values
**before** they reach the AI model. Runs as code — zero context cost, AI never
sees instructions.

```
AI runs:    echo $DATABASE_PASSWORD
Model sees: [REDACTED:ENV:DATABASE_PASSWORD]
```

## Detection

| Strategy | What it catches |
|----------|-----------------|
| Env vars | Names matching `SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH` (value > 8 chars) |
| Config file | Any `opencode.json`/`opencode.jsonc` string value whose key looks secret (`apiKey`, `Authorization`, `DB_PASSWORD`) |
| `.env` files | `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.staging` in the project root and one directory down (`node_modules`, `.git`, `dist`, `build`, `.venv`, `vendor` skipped) |
| Custom patterns | Literal values + regex from `secrets.local` |
| Known formats | OpenAI/Groq `sk-`, `gsk_`, Stripe, AWS, GitHub, GitLab, npm, PyPI, HuggingFace, DigitalOcean, Shopify, SendGrid, Slack, Google, Twilio, Telegram, Supabase `sbp_`, Replicate `r8_`, Azure `AccountKey=`, JWT, `Bearer`, PEM keys, connection strings |
| Inline key/value | `db_password: x`, `AWS_SECRET_ACCESS_KEY=z`, `awsSecretAccessKey: w`, quoted keys (`"api_key": "..."`) |
| CLI flags | `--password hunter2`, `--token=abc123` |

### Key matching

A key is split on camelCase and non-alphanumerics, then lowercased. It counts as
secret if any part is a known word (`password`, `passwd`, `pass`, `pwd`,
`passphrase`, `passcode`, `pin`, `otp`, `secret`, `token`, `apikey`,
`credential`, `privatekey`, `accesskey`, `secretkey`, `clientsecret`, `auth`,
`authorization`, `bearer`, `cookie`, `dsn`) or if two adjacent parts form a
known pair (`api key`, `secret key`, `private key`, `access key`,
`signing key`, `encryption key`, `master key`, `client secret`,
`refresh token`, `auth token`, `session id`, `conn string`,
`connection string`).

So prefixed keys (`db_password`), suffixed keys (`secret_key`), and camelCase
keys (`awsSecretAccessKey`) are all caught.

### Value guard

A matched value is left alone when it reads like code or config:

- `getToken()`, `path\\to\\file`, template strings (`${SECRET}`), backticks
- dotted chains (`process.env.PASSWORD`, `req.headers.token`)
- bare all-caps identifiers (`PASSWORD`)
- plain URLs (`https://...`)
- `[REDACTED:...]` already
- false positives: `true`, `null`, `changeme`, `test`, `bearer`, `optional`,
  `unset`, etc.

`const token = getToken()`, `password: process.env.PASSWORD`, and
`secret: ${SECRET}` pass through untouched; real values do not.

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

1. Clones the repo to `~/.config/opencode/plugins/the-vanishing-duck/`
2. Finds your opencode config and prints the line to add by hand
3. Creates the data dir at `~/.config/the-vanishing-duck/`
4. Scans env vars, `.env` files, config values
5. Lets you add custom literals + regex patterns interactively
6. Tests scrubbing

The script never edits `opencode.jsonc`. Register the plugin yourself by adding
the printed path (with a trailing comma) to the `plugins` array:

```json
  "/Users/you/.config/opencode/plugins/the-vanishing-duck",
```

OpenCode loads local plugin paths; restart after adding it.

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

The file is re-read when its mtime changes, so edits apply without a restart.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `VANISHING_DUCK_DIR` | `~/.config/the-vanishing-duck` | Data directory (log, custom patterns) |
| `VANISHING_DUCK_MAX_SIZE` | `512000` | Bytes above which the literal pass is skipped |

## Hooks

### Tool output

Hooks `tool.execute.after`, before output enters model context. Every tool is
scrubbed except `todowrite`, `todoread`, and `skill`. Error results
(`status === "error"`) are scrubbed too.

Text parts in `result.content` are scrubbed. If there is no text part, the
plugin falls back to `result.output.output`. Both are never scrubbed in the
same run.

When redactions happen, the last scrubbed text gets a notice:

```
[the-vanishing-duck: 3 value(s) redacted]
```

### Size policy

Regex, key/value and flag passes always run. Above `MAX_SCRUB_SIZE` (512 KB),
the literal-map pass is skipped for speed; the notice then reads
`(literal pass skipped: output too large)`.

### Chat messages

Hooks the `prompt` event and scrubs `event.prompt.text` before the model sees
it.

## Redaction log

Local log at `~/.config/the-vanishing-duck/redaction.log`:

```
[2026-09-14T10:30:00Z] session=abc123 tool=shell redacted=ENV:DATABASE_PASSWORD#1f3c9a2b
```

Each entry records the label plus a short SHA-256 of the value. No raw value and
no preview ever reaches the log. The file is chmod `600`. When it passes 1 MB it
is renamed to `redaction.log.1` and a fresh log starts.

## Limitations

- Binary/compiled files — output is binary garbage, regex won't match
- Very short values (<4 chars) — not matched, to avoid false positives
- Base64/encrypted secrets — no readable pattern to match
- Secrets in images/PDFs — not scanned

No tool catches 100%. This covers env vars, `.env` files, config files, known
formats, inline key/value pairs, CLI flags, and custom patterns.

## License

MIT
