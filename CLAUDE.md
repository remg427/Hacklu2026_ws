# SOC Detections

Detection engineering repository for Example Corp SOC

**Organisation:** Example Corp

## OpenTide detection repository

This repository uses [OpenTide](https://pypi.org/project/opentide/) for detection-as-code.

### Commands

```bash
opentide validate
opentide generate
opentide deploy --dry-run
```

### Layout

- Threat vectors: `objects/threats/`
- Objectives: `objects/objectives/`
- Rules: `objects/rules/`

### Agent skills

Project skills live under `.claude/skills/`. Start with `opentide-detection-rule` for validate/generate/deploy guidance.

Run `opentide setup mcp` to connect Claude Code to the MCP server (`opentide mcp start`).
