# Step 1 — Repository set-up log

Bootstrap of the **SOC Detections** repository (Example Corp) with OpenTide `0.16.0`.
Every repository artefact below was produced by the `opentide` CLI only — no files were hand-written during set-up.

## Environment

```bash
python3 -m venv ../.venv-opentide                    # venv kept outside the repo so the workspace stays clean
../.venv-opentide/bin/pip install "opentide==0.16.0" # pin the exact release
export PATH=../.venv-opentide/bin:$PATH
```

```bash
# This python.org build ships no OpenSSL CA bundle, so urllib (used by the skills
# installer) fails cert verification. Point it at the venv's certifi bundle.
export SSL_CERT_FILE="$(python -c 'import certifi;print(certifi.where())')"
```

Two machine-local gotchas worth recording, neither caused by OpenTide:

- **No CA bundle** — see the `SSL_CERT_FILE` export above. Without it
  `opentide setup skills` reports the catalogue as unreachable even though the
  network is fine.
- **x86_64 `git`** — `/usr/local/bin/git` is an Intel binary, so the pre-commit
  hook it spawns inherits x86_64 and the arm64-only `pydantic_core` wheel fails
  to load (`incompatible architecture`). The hook correctly refused the commit.
  Use the universal `/usr/bin/git` (or any arm64 build) on this machine.

## Commands

| # | Command | Comment |
|---|---------|---------|
| 1 | `git init` | Empty repo first; the CLI detects the Git worktree and adapts (CI default branch, hook install). Initial branch is `master`. |
| 2 | `opentide setup repo --path . --name "SOC Detections" --org "Example Corp" --description "Detection engineering repository for Example Corp SOC" --platform sentinel --platform splunk --yes` | Scaffolds `objects/`, `docs/`, `.opentide/`, `.gitignore`, `README.md`. `--platform` already writes the enabled platform TOMLs. |
| 3 | `opentide setup platforms --path . --sentinel --splunk --yes` | Explicit platform step; reported *already present* because step 2 created both. Kept for an auditable trail. |
| 4 | `opentide setup ci github --path . --default-branch master --yes` | Writes `.github/workflows/opentide.yml` — validate, generate, staging deploy on PR, production deploy + docs on `master`, inflight shard jobs. Platform secrets are listed in the header. |
| 5 | `opentide setup mcp --path . --claude-code --generic --yes` | `.mcp.json` for Claude Code (`OPENTIDE_REPO_ROOT=${CLAUDE_PROJECT_DIR}`) and `opentide.mcp.json` for any generic agent host. Both launch `opentide mcp start` on stdio. |
| 6 | `opentide setup skills --path . --claude-code --generic --all --name "SOC Detections" --org "Example Corp" --description "Detection engineering repository for Example Corp SOC" --yes` | Installs the full catalogue (31 skills) into `.agents/skills/`, mirrors it to `.claude/skills/`, and writes `AGENTS.md` + `CLAUDE.md`. Needed two passes: the unauthenticated GitHub tree API (60 req/h per IP) was exhausted, so the command was re-run after the window refilled. Re-runs are idempotent and resume where they stopped. |
| 7 | `opentide setup hooks --path . --install --yes` | Writes `.pre-commit-config.yaml` and `.opentide/hooks/pre-commit`, and installs `.git/hooks/pre-commit`. Both run `opentide validate --strict`; bypass with `OPENTIDE_SKIP_HOOKS=1`. |
| 8 | `opentide generate` | Full pipeline — docs, exports, vocabularies, templates, JSON schemas, VS Code snippets. Exit 0. |
| 9 | `opentide validate --strict` | Exit 0: *validation passed, but no detection objects were found* — expected, the catalogue is still empty. |
| 10 | `git checkout -b Step-1-set-up` | Branch holding the set-up. |

## Result

```
opentide info
  Version                    0.16.0
  Rules / Threats / Objectives   0 / 0 / 0
  Microsoft Sentinel         enabled=True  [deploy, validate]
  Splunk Enterprise Security enabled=True  [deploy, validate]
  (all other platforms       enabled=False)
```

Layout:

```
.agents/skills/      31 skills (generic agents)
.claude/skills/      same catalogue (Claude Code)
.claude/ .mcp.json   Claude Code MCP server
opentide.mcp.json    generic agent MCP server
AGENTS.md CLAUDE.md  agent entrypoints
.github/workflows/   GitHub Actions pipeline
.opentide/           platform configs, schemas, templates, exports, hooks
objects/             rules, threats, objectives (empty)
docs/                generated documentation
```

## Next

Author the first object (`objects/threats/`, then `objects/rules/`) from the generated
templates in `.opentide/templates/`, and add a tenant to
`.opentide/configurations/platforms/{sentinel,splunk}.toml` to unlock live query
validation and deployment.
