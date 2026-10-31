#!/usr/bin/env bash
# the-vanishing-duck — install + setup (one script)
# Clones repo, registers plugin, scans for secrets, lets you add custom patterns.
#
# Run:
#   curl -fsSL https://raw.githubusercontent.com/Herdanis/the-vanishing-duck/main/install.sh | bash
#
# Or clone first:
#   git clone https://github.com/Herdanis/the-vanishing-duck.git
#   bash the-vanishing-duck/install.sh

set -euo pipefail

REPO_URL="https://github.com/Herdanis/the-vanishing-duck.git"
CLONE_DIR="$HOME/.config/opencode/plugins/the-vanishing-duck"
DATA_DIR="${VANISHING_DUCK_DIR:-$HOME/.config/the-vanishing-duck}"
SECRETS_FILE="$DATA_DIR/secrets.local"
LOG_FILE="$DATA_DIR/redaction.log"
CONFIG_FILE=""
PLUGIN_ENTRY="$CLONE_DIR"

# ============================================
# Helpers
# ============================================

info()    { printf "\033[34m▸\033[0m %s\n" "$1"; }
ok()      { printf "\033[32m✓\033[0m %s\n" "$1"; }
warn()    { printf "\033[33m!\033[0m %s\n" "$1"; }
fail()    { printf "\033[31m✗\033[0m %s\n" "$1"; exit 1; }

confirm() {
    printf "\033[36m?\033[0m %s [y/N] " "$1"
    read -r
    [[ "$REPLY" =~ ^[Yy]$ ]]
}

find_config() {
    for f in \
        "$HOME/.config/opencode/opencode.jsonc" \
        "$HOME/.config/opencode/opencode.json" \
        "$(pwd)/opencode.jsonc" \
        "$(pwd)/opencode.json" \
        "$(pwd)/.opencode/opencode.json"; do
        if [[ -f "$f" ]]; then
            CONFIG_FILE="$f"
            return 0
        fi
    done
    return 1
}

# ============================================
# Banner
# ============================================

printf "\n"
printf "\033[35m╦ ╦┌─┐┌─┐┌─┐┬ ┬┌┬┐┌─┐┬─┐┬┌─┐┌┬┐\033[0m\n"
printf "\033[35m║║║├┤ └─┐│ ││ │ ││├┤ ├┬┘│├┤  │ \033[0m\n"
printf "\033[35m╚╩╝└─┘└─┘└─┘└─┘─┴┘└─┘┴└─┴└─┘ ┴ \033[0m\n"
printf "  Secret scrubbing for OpenCode\n\n"

# ============================================
# Step 1: Pre-flight
# ============================================

info "Step 1: Checking prerequisites..."

command -v git >/dev/null 2>&1 || fail "git not found. Install: brew install git"
command -v bun >/dev/null 2>&1 || command -v node >/dev/null 2>&1 || warn "Neither bun nor node found — OpenCode needs one to run plugins"

ok "Prerequisites satisfied"

# ============================================
# Step 2: Clone repo
# ============================================

printf "\n"
info "Step 2: Installing plugin"

if [[ -d "$CLONE_DIR/.git" ]]; then
    info "Repo exists at $CLONE_DIR — pulling latest..."
    git -C "$CLONE_DIR" pull --quiet
    ok "Repo updated"
else
    info "Cloning to $CLONE_DIR..."
    mkdir -p "$(dirname "$CLONE_DIR")"
    git clone --quiet "$REPO_URL" "$CLONE_DIR"
    ok "Repo cloned"
fi

# ============================================
# Step 3: Register plugin
# ============================================

printf "\n"
info "Step 3: Register plugin in opencode config"

if find_config; then
    ok "Config found: $CONFIG_FILE"
else
    CONFIG_FILE="$HOME/.config/opencode/opencode.jsonc"
    warn "No opencode config found. Create $CONFIG_FILE and add the line below."
fi

if [[ -f "$CONFIG_FILE" ]] && grep -q "the-vanishing-duck" "$CONFIG_FILE" 2>/dev/null; then
    ok "Plugin already registered in config"
else
    warn "Add this line to the \"plugins\" array in $CONFIG_FILE by hand:"
    printf "\n    \"%s\",\n\n" "$PLUGIN_ENTRY"
    info "Nothing in the config is edited automatically."
fi

# ============================================
# Step 4: Create data dir
# ============================================

printf "\n"
info "Step 4: Setting up data directory"

mkdir -p "$DATA_DIR"

if [[ ! -f "$SECRETS_FILE" ]]; then
    if [[ -f "$CLONE_DIR/secrets.local.template" ]]; then
        cp "$CLONE_DIR/secrets.local.template" "$SECRETS_FILE"
        ok "Created secrets.local from template"
    else
        touch "$SECRETS_FILE"
        ok "Created empty secrets.local"
    fi
else
    ok "secrets.local already exists — kept"
fi

touch "$LOG_FILE"
ok "Data dir ready: $DATA_DIR"

# ============================================
# Step 5: Scan env vars
# ============================================

printf "\n"
info "Step 5: Scanning environment variables"
printf "These will be auto-scrubbed from tool output + chat:\n\n"

env_count=0
while IFS='=' read -r name value; do
    if echo "$name" | grep -qiE '(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH)'; then
        if [[ ${#value} -gt 8 ]]; then
            preview="${value:0:3}...${value: -3}"
            printf "  \033[33m%-40s\033[0m  %s\n" "$name" "$preview"
            env_count=$((env_count + 1))
        fi
    fi
done < <(env)

if [[ $env_count -eq 0 ]]; then
    ok "No env vars with secret-like names found"
else
    ok "$env_count env var(s) will be auto-scrubbed"
fi

# ============================================
# Step 6: Scan .env files
# ============================================

printf "\n"
info "Step 6: Scanning .env files in current directory"

env_file_count=0
for f in .env .env.local .env.production .env.development .env.staging; do
    if [[ -f "$f" ]]; then
        secret_lines=0
        while IFS= read -r line; do
            if echo "$line" | grep -qiE '^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.{4,}'; then
                name=$(echo "$line" | cut -d'=' -f1)
                if echo "$name" | grep -qiE '(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH)'; then
                    secret_lines=$((secret_lines + 1))
                fi
            fi
        done < "$f"
        printf "  \033[33m%s\033[0m — %d secret(s)\n" "$f" "$secret_lines"
        env_file_count=$((env_file_count + 1))
    fi
done

if [[ $env_file_count -eq 0 ]]; then
    ok "No .env files in current directory"
else
    ok "$env_file_count .env file(s) will be auto-scanned"
fi

# ============================================
# Step 7: Scan config apiKey values
# ============================================

printf "\n"
info "Step 7: Scanning opencode config for apiKey values"

config_count=0
for f in \
    "$HOME/.config/opencode/opencode.jsonc" \
    "$HOME/.config/opencode/opencode.json"; do
    if [[ -f "$f" ]]; then
        while IFS= read -r match; do
            val=$(echo "$match" | sed 's/.*"apiKey"\s*:\s*"//;s/".*//')
            if [[ ${#val} -gt 8 ]]; then
                preview="${val:0:3}...${val: -3}"
                printf "  \033[33m%-40s\033[0m  %s\n" "$(basename "$f")" "$preview"
                config_count=$((config_count + 1))
            fi
        done < <(grep -oE '"apiKey"\s*:\s*"[^"]+"' "$f" 2>/dev/null || true)
    fi
done

if [[ $config_count -eq 0 ]]; then
    ok "No apiKey values in config files"
else
    ok "$config_count config apiKey value(s) will be auto-scrubbed"
fi

# ============================================
# Step 8: Add custom secrets (interactive)
# ============================================

printf "\n"
info "Step 8: Custom secrets"
printf "Add literal secret values that should be redacted.\n"
printf "These get matched exactly in tool output + chat.\n\n"

added=0
if confirm "Add a custom secret value?"; then
    while true; do
        printf "  Enter the secret value: "
        read -r value
        if [[ -z "$value" || ${#value} -lt 4 ]]; then
            warn "Value too short (min 4 chars). Skipped."
        else
            echo "$value" >> "$SECRETS_FILE"
            preview="${value:0:3}...${value: -3}"
            ok "Added: $preview"
            added=$((added + 1))
        fi
        if ! confirm "Add another?"; then
            break
        fi
    done
fi

if [[ $added -eq 0 ]]; then
    ok "No custom secrets added — auto-detection still active"
else
    ok "$added custom secret(s) added to secrets.local"
fi

# ============================================
# Step 9: Add custom regex patterns (interactive)
# ============================================

printf "\n"
info "Step 9: Custom regex patterns"
printf "Add regex patterns for secret formats this tool doesn't know.\n"
printf "Format: regex pattern + optional label\n\n"

if confirm "Add a custom regex pattern?"; then
    while true; do
        printf "  Regex pattern: "
        read -r pattern
        if [[ -z "$pattern" ]]; then
            warn "Empty pattern. Skipped."
        else
            printf "  Label (optional, e.g. COMPANY_TOKEN): "
            read -r label
            if [[ -n "$label" ]]; then
                echo "regex: $pattern as $label" >> "$SECRETS_FILE"
                ok "Added regex: $pattern as $label"
            else
                echo "regex: $pattern" >> "$SECRETS_FILE"
                ok "Added regex: $pattern"
            fi
        fi
        if ! confirm "Add another?"; then
            break
        fi
    done
else
    ok "No custom regex patterns added"
fi

# ============================================
# Step 10: Test scrubbing
# ============================================

printf "\n"
info "Step 10: Testing scrubbing"

test_val="sk-test-1234567890abcdef"

if command -v bun >/dev/null 2>&1; then
    test_output=$(echo "$test_val" | bun -e "
const text = await new Response(Bun.stdin).text();
const re = /sk-[A-Za-z0-9]{20,}/g;
const m = text.match(re);
if (m) console.log('SCRUBBED: ' + text.replace(re, '[REDACTED:API_KEY]'));
else console.log('CLEAN: ' + text);
" 2>/dev/null || echo "SKIP")

    if [[ "$test_output" == *"REDACTED"* ]]; then
        ok "Scrubbing works: $test_output"
    else
        warn "Test did not match. Plugin still active — restart OpenCode to use it."
    fi
else
    warn "bun not found — skipping runtime test. Plugin still active after restart."
fi

# ============================================
# Summary
# ============================================

printf "\n"
printf "\033[32m┌──────────────────────────────────────────────────────┐\033[0m\n"
printf "\033[32m│  the-vanishing-duck installed + setup complete!      │\033[0m\n"
printf "\033[32m└──────────────────────────────────────────────────────┘\033[0m\n"
printf "\n"
printf "  Auto-detected:\n"
printf "    %d env var(s)\n" "$env_count"
printf "    %d .env file(s)\n" "$env_file_count"
printf "    %d config apiKey(s)\n" "$config_count"
printf "  Custom:\n"
printf "    %d literal value(s) in secrets.local\n" "$added"
printf "\n"
printf "  Files:\n"
printf "    Config:   %s\n" "$CONFIG_FILE"
printf "    Plugin:   %s\n" "$CLONE_DIR"
printf "    Data dir: %s\n" "$DATA_DIR"
printf "    Patterns: %s\n" "$SECRETS_FILE"
printf "    Log:      %s\n" "$LOG_FILE"
printf "\n"
printf "  \033[33mRestart OpenCode to activate the plugin.\033[0m\n"
printf "\n"
printf "  Check redactions after restart:\n"
printf "    tail -f %s\n" "$LOG_FILE"
printf "\n"
