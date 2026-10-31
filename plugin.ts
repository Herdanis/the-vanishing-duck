// the-vanishing-duck — OpenCode v2 plugin wrapper
//
// Detection and scrubbing live in lib.ts. This file only wires hooks.

import { statSync } from "node:fs"
import {
  SKIP_TOOLS,
  MAX_SCRUB_SIZE,
  SECRET_REGEXES,
  CUSTOM_PATTERNS_PATH,
  collectEnvSecrets,
  collectConfigSecrets,
  collectEnvFileSecrets,
  collectCustomPatterns,
  scrub,
  logRedactions,
} from "./lib"

type TextPart = { type: string; text?: string }

type ToolHookEvent = {
  tool: string
  sessionID?: string
  status?: "completed" | "error"
  result?: {
    content?: TextPart[]
    output?: { output?: string }
  }
}

type PromptHookEvent = {
  sessionID?: string
  prompt?: { text?: string }
}

type PluginContext = {
  location: { directory: string }
  tool: { hook(name: "execute.after", cb: (event: ToolHookEvent) => void): Promise<unknown> }
  session: { hook(name: "prompt", cb: (event: PromptHookEvent) => void): Promise<unknown> }
}

function notice(count: number, literalsSkipped: boolean): string {
  const suffix = literalsSkipped ? " (literal pass skipped: output too large)" : ""
  return `\n\n[the-vanishing-duck: ${count} value(s) redacted]${suffix}`
}

function mtime(path: string): number | null {
  try {
    return statSync(path).mtimeMs
  } catch {
    return null
  }
}

export default {
  id: "the-vanishing-duck",

  async setup(ctx: PluginContext) {
    const baseSecrets = new Map<string, string>()
    for (const [v, l] of collectEnvSecrets()) baseSecrets.set(v, l)
    for (const [v, l] of collectConfigSecrets()) baseSecrets.set(v, l)
    for (const [v, l] of collectEnvFileSecrets(ctx.location.directory)) baseSecrets.set(v, l)

    let custom = collectCustomPatterns()
    let customMtime = mtime(CUSTOM_PATTERNS_PATH)

    const patterns = () => {
      const secrets = new Map(baseSecrets)
      for (const [v, l] of custom.literals) secrets.set(v, l)
      return { secrets, regexes: [...SECRET_REGEXES, ...custom.regexes] }
    }

    const refreshCustom = () => {
      const m = mtime(CUSTOM_PATTERNS_PATH)
      if (m === null || m === customMtime) return
      customMtime = m
      try {
        custom = collectCustomPatterns(CUSTOM_PATTERNS_PATH)
      } catch {}
    }

    await ctx.tool.hook("execute.after", (event) => {
      if (SKIP_TOOLS.has(event.tool)) return
      const result = event.result
      if (!result) return
      refreshCustom()
      const { secrets, regexes } = patterns()

      const redactions: string[] = []
      let target: TextPart | undefined
      let literalsSkipped = false

      const parts = (result.content ?? []).filter(
        (p) => p.type === "text" && typeof p.text === "string" && p.text.length > 0,
      )

      if (parts.length > 0) {
        for (const part of parts) {
          const tooBig = part.text!.length > MAX_SCRUB_SIZE
          const res = scrub(part.text!, secrets, regexes, tooBig ? { literals: false } : undefined)
          if (res.redactions.length === 0) continue
          part.text = res.output
          target = part
          if (tooBig) literalsSkipped = true
          redactions.push(...res.redactions)
        }
      } else {
        const raw = result.output?.output
        if (typeof raw === "string" && raw.length > 0) {
          const tooBig = raw.length > MAX_SCRUB_SIZE
          const res = scrub(raw, secrets, regexes, tooBig ? { literals: false } : undefined)
          if (res.redactions.length > 0 && result.output) {
            result.output.output = res.output
            if (tooBig) literalsSkipped = true
            redactions.push(...res.redactions)
          }
        }
      }

      if (redactions.length === 0) return
      if (target) target.text += notice(redactions.length, literalsSkipped)
      logRedactions(redactions, event.tool, event.sessionID ?? "unknown")
    })

    await ctx.session.hook("prompt", (event) => {
      const text = event.prompt?.text
      if (!text) return
      refreshCustom()
      const { secrets, regexes } = patterns()
      const tooBig = text.length > MAX_SCRUB_SIZE
      const res = scrub(text, secrets, regexes, tooBig ? { literals: false } : undefined)
      if (res.redactions.length === 0) return
      event.prompt!.text = res.output
      logRedactions(res.redactions, "session.prompt", event.sessionID ?? "unknown")
    })
  },
}
