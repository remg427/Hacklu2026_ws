---
name: opentide-rule
description: Authors opentide Detection Rule objects — structured descriptions, response procedures an analyst can actually follow, exclusion discipline, and per-platform configurations wired to the signals they implement. Covers platform capability differences, signal traceability, and anti-patterns distilled from production corpora. Resolves object structure and platform keys from the installed engine instead of pinning fields. Pair with the relevant platform and query-language skills for syntax. Use when producing deployable detection content or updating existing rules.
---

# opentide Detection Rule (MDR)

An MDR is the **deployable artefact** — the detection rule that runs on a specific platform. It implements a DOM signal and carries the response metadata that guides analysts when the rule fires.

---

## Resolve the schema before authoring

Do not author from memory, and do not expect a field list in this skill. A
Detection Rule's structure is versioned, ships with the engine, and changes without
this skill changing. Resolve it from the installed version every time.

Two fields look like versions and mean different things. Confusing them is the
most common authoring mistake:

| Field | Means | Where it comes from |
|---|---|---|
| `metadata.schema` | the structural revision, `{family}::{major}.{minor}` | the template you resolve below |
| `metadata.version` | the content revision of this one object | you, on meaningful change; git holds the real history |

Never select a schema file using `metadata.version`. An object on content
version 4 can still declare the first structural revision.

Resolve the live structure in this order, stopping at the first that answers:

1. **MCP resources**, when the opentide MCP server is connected.
   `opentide://schemas/rule` returns the JSON Schema, resolved to the
   highest registered revision. `opentide://templates/rule` returns the
   authoring template. `opentide://vocabularies` lists the controlled
   vocabularies and `opentide://vocabularies/{name}` returns the allowed
   values of one -- read these instead of guessing at an enum, because members
   get added.
2. **Generated artefacts in the repository**, when no server is connected.
   `.opentide/schemas/` and `.opentide/templates/` hold one file per registered
   revision; take the one matching the declared `metadata.schema`.
3. **Generate them**, when neither exists: `opentide generate schemas` and
   `opentide generate templates`, or `opentide generate` for both. An empty
   schema or template list means this step has not been run -- that is the
   cause, not a missing object type.

Then read a neighbouring object of the same family for local convention, and
`opentide --json info rules` to see what already exists before adding
something that overlaps.

Repository layout is not fixed either. A CoreTide-era corpus uses different
family names and directories than a current one, and `opentide migrate objects`
is what moves it forward -- the repository owner's decision, not one to take
mid-task. Derive paths from the template you just resolved rather than assuming
either layout.

## Why there is no field table here

Required and optional status, enum members, controlled vocabularies and
deprecations all move with the schema revision. A copy of them here would go
stale without anything failing loudly, which is worse than having no copy at
all.

What this skill carries is the part that does not move: when a Detection Rule is the
right object to reach for, how to decide what belongs in it, and what separates
a good one from a passable one.

For *what fields exist*, read the schema. For *is this valid*, run
`opentide validate`, or `opentide lint` for style, or the `validate_rule` and
`validation_report` MCP tools for a single object. A validator error outranks
anything written in this skill.

## Description — structured three-section format

The best MDRs use a consistent structure that separates technical details from detection criteria and exclusions:

```yaml
description: |
  #### MDR Technical Details
  This rule queries [table] for [behaviour pattern]. It targets
  [specific technique] as documented in [DOM reference].

  #### Detection Criteria
  - Threshold: `failureCountThreshold = 30` (agreed with stakeholders)
  - Time window: 1 hour sliding
  - Entity scope: per-user, per-IP

  #### Exclusion Criteria
  - Service accounts matching `svc_*` pattern excluded via watchlist
  - Known VPN egress IPs excluded via `known_egress_ips` lookup
  - Rationale: [why each exclusion is safe]
```

**Rules**:
- Use YAML `|` block scalar always.
- Separate **what** (technical details), **when** (detection criteria), and **what's excluded** (exclusion criteria).
- Document thresholds with rationale ("agreed with stakeholders", "based on 30-day baseline").
- Reference the DOM signal this MDR implements.

---

## Platform configurations

Which platforms a rule may configure, and the structure inside each
configuration block, come from the engine -- not from this skill.

- `opentide://platforms`, or `opentide --json info --platform <name>`, lists the
  platforms the installed engine knows and what each one can do. Capability is
  not uniform: some can be deployed to *and* have their queries validated,
  others can only be deployed to. Never promise validation a platform cannot
  perform.
- The schema you resolved carries the configuration structure for each platform
  key.
- A configuration key matches **exactly**. `sentinel` and `sentinel_one` are
  different platforms, and a near-miss key configures nothing while looking
  correct.

What this skill asserts is the part the schema does not:

- **One configuration implements one signal.** The link back to the objective's
  signal is what makes a rule reviewable. A configuration implementing "the
  general idea" of an objective is one nobody can audit.
- **Query authoring belongs to the platform skill.** This skill governs what
  the rule must detect and how it is structured; the platform skill holds table
  schemas, operators and platform constraints. Load the platform skill for
  syntax, paired with the query-language skill where one applies.
- **Validate queries with the engine, not by eye.** Use `opentide validate` or
  the `validate_query` and `validate_rule` MCP tools on a platform that
  supports it. A query never executed against its platform is a draft.


## Response procedure authoring

The `response.procedure` block is what analysts see when the rule fires. Quality here directly impacts mean-time-to-respond.

### Great procedure pattern

> The `searches` block below uses KQL as an example — adapt the query language to the target platform.

```yaml
procedure:
  analysis: |
    1. Review the alert details and identify the affected user/device.
    2. Navigate to [Portal] > [Section] > [Page] to view the full event context.
    3. Run the supporting search below to identify related activity.
    4. Check the exclusion watchlist — if the entity is listed, close as FP.
    5. If confirmed TP, escalate to [team] and proceed to containment.
  searches:
    - purpose: Identify related authentication activity for the affected user
      system: sentinel
      query: |
        SigninLogs
        | where TimeGenerated > ago(24h)
        | where UserPrincipalName == "{{UserPrincipalName}}"
        | project TimeGenerated, IPAddress, Location, ResultType, AppDisplayName
  containment: |
    1. Disable the affected account via Entra ID.
    2. Revoke all active sessions.
    3. Reset credentials and re-enrol MFA.
    4. Notify the user's manager.
```

### Mediocre procedure pattern

```yaml
procedure:
  analysis: "Investigate the alert."
```

---

## Exclusion discipline

Exclusions are the most dangerous part of an MDR — they create permanent blind spots.

### Rules

1. Every exclusion must have a `reason` explaining why it is safe.
2. Exclusions are **tenant-scoped** — what's safe in one environment may not be in another.
3. Use `let` variables for exclusion lists to make them visible and auditable.
4. Review exclusions quarterly — stale exclusions become attacker-friendly territory.
5. Document expected FP sources in the MDR `description` (Exclusion Criteria section).

```yaml
exclusions:
  - tenant: production-eu
    reason: Vulnerability scanner generates high-volume 4625 events
    let: excluded_scanners
    query: |
      let excluded_scanners = datatable(IPAddress: string) [
          "10.0.1.50", "10.0.1.51"
      ];
```

---

## Skill pairing for query authoring

| Stack | Skill pairing |
|-------|----------------|
| Sentinel & Log Analytics | `kusto-query-language` + `microsoft-sentinel` |
| Defender for Endpoint | `kusto-query-language` + `microsoft-defender-endpoint` |
| Splunk SPL / ES correlation | `splunk-spl-processing` |
| CrowdStrike Falcon | `crowdstrike-falcon` |
| SentinelOne Singularity | `sentinelone-singularity` |
| Carbon Black Cloud | `carbon-black-cloud` |
| HarfangLab | `harfanglab` |

Avoid shipping vendor-specific artefacts your manifest does not advertise — explicitly annotate gaps ("Sentinel backlog item #123") instead of placeholders that read as executable content.

---

## Anti-patterns

| Anti-pattern | Fix |
|---|---|
| **Terse one-line description** | Use the three-section structure: Technical Details, Detection Criteria, Exclusion Criteria |
| **No `procedure` block** | Every `PRODUCTION` rule needs analyst handling guidance |
| **No `playbook` link** | Link to the formal playbook when one exists |
| **Empty/commented-out platform blocks** | Remove platforms you don't target. Don't leave `#sentinel:` noise. |
| **Hardcoded org-specific macros without docs** | Document what macros resolve to, or use inline `let` variables |
| **Risk scores without justification** | Document why `score: 5` vs `score: 10` |
| **Missing entity/risk mappings** | Map at minimum: Account, IP, Host (Sentinel) or user/system risk objects (Splunk) |
| **Schema version drift** | Always check the live template for the current schema version |
| **Inline comment as sole DOM linkage** | Verify the `detection_model` UUID exists in the DOM library |
| **Missing containment on High-severity rules** | High-severity rules must have containment guidance |
| **Inconsistent query output columns** | Standardise output column names across rules for the same platform |

---

## Quality checklist

- [ ] `name` uses verb-noun pattern with domain prefix.
- [ ] `metadata.schema` matches the current live template version.
- [ ] `detection_model` UUID verified against DOM library.
- [ ] `description` uses three-section structure (Technical Details, Detection Criteria, Exclusion Criteria).
- [ ] `response.alert_severity` calibrated: High = immediate, Medium = same-day, Low = RBA only.
- [ ] `response.responders` populated for `PRODUCTION` rules.
- [ ] `response.procedure.analysis` has numbered analyst steps.
- [ ] `response.procedure.searches` has at least one supporting query for Medium+ severity.
- [ ] `response.procedure.containment` populated for High severity rules.
- [ ] Platform `configurations.*.status` set (`PRODUCTION`, `DEVELOPMENT`, `DEPRECATED`).
- [ ] Platform `configurations.*.query` follows the relevant query language + platform skill.
- [ ] Entity mappings (Sentinel) or risk objects (Splunk) populated.
- [ ] Exclusions carry `reason` and are tenant-scoped.
- [ ] No commented-out platform blocks remain.
- [ ] Thresholds documented with rationale.
- [ ] Risk scores documented with rationale.

---

## Collaboration with neighbouring skills

- Upstream **`opentide-objective`** for signal specifications.
- Upstream **`opentide-threat`** for threat context.
- **`detection-engineering`** for hunt-to-rule conversion lifecycle.
- **`mitre-attack`** for technique precision in platform metadata.
- **Platform/query skills** for query authoring discipline.
