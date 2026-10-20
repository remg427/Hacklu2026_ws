# SOC Detections — Agent Guide

Detection engineering repository for Example Corp SOC

**Organisation:** Example Corp

## Quick start

```bash
opentide setup          # interactive repository onboarding
opentide validate
opentide generate
opentide deploy --dry-run
```

## Object layout

- `objects/threats/` — threat vectors
- `objects/objectives/` — detection objectives
- `objects/rules/` — MDR rules
- `.opentide/configurations/` — platform and visibility configuration
- `.opentide/schemas/` — generated JSON schemas (via `opentide generate`)
- `.opentide/templates/` — generated object templates

## Skills

See `.agents/skills/opentide-detection-rule/SKILL.md` for detection engineering workflows.

## MCP

Run `opentide setup mcp` to write editor MCP config that runs `opentide mcp start`.
