---
name: threat-hunting
description: Threat hunting hypothesis discipline using the ABLE framework (Actor, Behaviour, Location, Evidence), hypothesis quality scoring (confidence, relevance, priority, effort, scope), evidence-platform decision matrix, hypothesis archetypes (baseline anomaly, frequency-based, behavioural sequence), data-gap analysis, anti-pattern checks, and the bridge from validated hunts into opentide TVM/DOM/MDR objects. Use when generating hunt leads from intelligence, scoring hunting hypotheses, decomposing behaviour into observable telemetry, or feeding hunt outcomes back into Threat Vectors and Detection Objectives.
---

# Threat hunting — hypothesis discipline

This skill encodes the rigour of hypothesis-driven hunting (ABLE framework, scoring, anti-pattern checks) and the conversion path from validated hunts into opentide content. For language- or platform-level mechanics see the relevant skills (`kusto-query-language`, `microsoft-sentinel`, `microsoft-defender-endpoint`, `splunk-spl-processing`, etc.). For converting validated hunts into deployable rules, see `detection-engineering`.

> **opentide bridge**:
> - Hunt **hypothesis** ↔ TVM `chaining`/`terrain` narrative + DOM analytic intent.
> - Hunt **queries** ↔ DOM `signals` (logical specification) and MDR `configurations.*` (deployable expression).
> - Hunt **verdict** ↔ DOM/MDR maturity progression and TVM evidence updates.

---

## 1. Hypothesis lifecycle

```
Intelligence intake
   │
   ▼
Phase 1: Hypothesis creation     ←── this skill
   │
   ▼
Phase 2: Query authoring         ←── language + platform skills
   │
   ▼
Phase 3: Query execution         ←── platform-specific runner / hunting console
   │
   ▼
Phase 4: Result interpretation   ←── this skill (verdict, pivots, hunt report)
   │
   ▼
Hunt report → DOM/MDR conversion ←── detection-engineering, opentide-detection-* skills
```

---

## 2. Phase 1 — Hypothesis creation

### Step 1 — Extract key claims

Read the source intelligence and identify each discrete **threat-behaviour claim** — a specific statement about what an actor is doing or can do.

**Rule**: Each claim mapping to a distinct, detectable TTP becomes its own hypothesis. **Do not** combine multiple TTPs (anti-pattern AP-H2: Kitchen Sink — see `kusto-query-language/references/Hypothesis-Anti-Patterns.md`).

### Step 2 — Apply the ABLE framework

For each claim, formulate an ABLE-complete hypothesis:

| Component | Question | Source |
|---|---|---|
| **A**ctor | Who? | Named from intelligence |
| **B**ehaviour | What TTP, specifically? | Map to MITRE ATT&CK |
| **L**ocation | Where in the environment? | Target profile + organisational knowledge |
| **E**vidence | What telemetry detects it? | Platform table/index catalogues (see relevant platform skill) |

**Completeness check**:

| Score | Action |
|---|---|
| 4/4 | Proceed |
| 3/4 (Location missing) | Infer from target profile or set scope to `ENTIRE_ENVIRONMENT` with justification |
| 3/4 (Evidence missing) | Check platform table references. If no table covers the behaviour, document as a `data_gap` and skip if blocked |
| ≤ 2/4 | **Do not** create hypothesis — insufficient information |

### Step 2b — Evidence platform selection

Map each behavioural component to the telemetry domain and platform family that captures it. Exact table/index names are platform-specific — consult the relevant platform skill.

| Evidence domain | Platform family | Telemetry type |
|---|---|---|
| Process execution, file operations, registry | EDR | Process creation logs, file event logs, registry modification logs |
| Device-level network connections | EDR | Network connection / socket logs |
| Email delivery, URL clicks | Email security / XDR | Mail flow logs, URL click telemetry |
| Identity / sign-in activity | IdP / SIEM | Authentication logs, sign-in logs (interactive + non-interactive) |
| Cloud directory configuration | IdP / SIEM | Directory audit / change logs |
| Cloud resource operations | SIEM / cloud-native | Cloud activity / control-plane audit logs |
| SaaS activity | SIEM / CASB | Unified audit logs, application activity logs |
| Network appliance logs | SIEM | Firewall, proxy, IDS/IPS logs (CEF, syslog, vendor-native) |
| OS security events | SIEM / EDR | Security event logs (Windows Security, auditd, etc.) |
| DNS resolution | SIEM / DNS security | DNS query and response logs |

> Consult platform skills for exact table/index names: `microsoft-sentinel`, `microsoft-defender-endpoint`, `splunk-spl-processing`, `crowdstrike-falcon`, `sentinelone-singularity`, `carbon-black-cloud`, `harfanglab`.

**Cross-platform hypotheses** are valid: a single hypothesis may reference evidence on **both** an EDR and a SIEM platform. Author **separate queries per platform** with the correct platform tag — never attempt cross-platform joins.

### Step 2c — Data-gap analysis

If no table on any available platform covers a behavioural component, register a `data_gap`:

```yaml
data_gaps:
  - domain: Network appliance logs
    platform: BOTH
    telemetry: Firewall / proxy logs (CEF, syslog, or vendor-native)
    description: Firewall/proxy logs needed but not ingested
    impact: BLIND_SPOT
```

| Impact | Meaning | Action |
|---|---|---|
| `PARTIAL_COVERAGE` | Other tables/platforms partially cover | Proceed; note limitation |
| `BLIND_SPOT` | Specific vector undetectable, others covered | Proceed; downgrade confidence |
| `HYPOTHESIS_BLOCKED` | Cannot meaningfully test | May create with confidence `LOW`; verdict will be `INCONCLUSIVE` |

In opentide, blind spots and blocked hypotheses feed back into the corresponding TVM `terrain.requirements` and DOM `data_requirements` to communicate gaps to coverage owners.

### Step 3 — Write the rationale

The rationale links **intelligence → hypothesis → detection opportunity**:

1. **What intelligence triggered this?** Reference specific source quotes.
2. **Why is it plausible in our environment?** Sector, tech stack, geography.
3. **What is the detection opportunity?** Why available telemetry can catch this.

Template:

```
Source intelligence from [source_name] (ref: [source_id]) states "[verbatim quote]".
This is relevant to [organisation] because [specific connection].
Detection is possible through [table/telemetry] on [platform] because [why].
```

### Step 4 — Score confidence

| Score | Criteria | Source pattern |
|---|---|---|
| HIGH | Named credible source + confirmed active exploitation + environment exposed | Confirmed CTI vendor analysis + uses targeted tech |
| MEDIUM | Credible source + plausible but unconfirmed OR confirmed but unclear exposure | Industry report + sector mentioned |
| LOW | Indirect intelligence, dated source, or speculative connection | General advisory > 6 months old |

**Confidence rationale must**: name the source, assess credibility, state whether activity is confirmed or theoretical, connect to environmental exposure.

### Step 5 — Score relevance

| Score | Criteria | Action implication |
|---|---|---|
| CRITICAL | Targets sector + geography + specific technology in use | Hunt immediately |
| HIGH | Targets sector or technology in use, but not all three | Hunt within standard cycle |
| MODERATE | General threat with indirect applicability | Hunt if resources available |
| LOW | Peripheral awareness, different sector/geography | Document only |

**Relevance rationale must**: reference specific organisational assets, sectors, or technologies; explain overlap (or lack of) between threat targeting and organisational exposure.

### Step 6 — Set priority and effort

| Priority | Timeline | When |
|---|---|---|
| URGENT | Within 24 h | Confidence HIGH + Relevance CRITICAL, active exploitation |
| HIGH | Within 72 h | Confidence HIGH + Relevance HIGH, or MEDIUM + CRITICAL |
| STANDARD | Within 1 week | Anything else worth hunting |

| Effort | Definition |
|---|---|
| MINIMAL | Run query, triage < 10 expected results |
| MODERATE | Multi-query correlation, 10–100 expected results |
| SIGNIFICANT | Manual investigation required, > 100 results or multi-day effort |

### Step 7 — Source references

Every hypothesis carries at least one source reference with verbatim quotes:

```yaml
source_references:
  - url: https://example.com/article
    title: Source Title
    quotes:
      - Verbatim quote 1
      - Verbatim quote 2
```

**URL rule**: Use the original article URL or alert payload URL. **Never fabricate or guess** portal URLs.

### Step 8 — Anti-pattern self-review

Before locking the hypothesis, scan for:

| Anti-pattern | Trigger | Reference |
|---|---|---|
| AP-H1 (Tautology) | Could apply to any organisation? | `kusto-query-language/references/Hypothesis-Anti-Patterns.md` |
| AP-H2 (Kitchen Sink) | Covers > 1 TTP? | Split |
| AP-H3 (Orphan) | No source reference? | Add citation |
| AP-H4 (Technology Hunt) | Hunting a tool, not a behaviour? | Narrow to behavioural chain |
| AP-H5 (Time Traveler) | Source > 6 months without justification? | Add recency context or justification |

---

## 3. Hypothesis archetypes

### Archetype 1 — Baseline anomaly

For behaviours where "normal" must be established before "abnormal" can be detected.

> **Iteration cost**: typically 2–3 iterations to tune thresholds. Set effort ≥ MODERATE.

**Template**: `[Actor] may be causing anomalous [metric] in [location], detectable via deviation from [timeframe] baseline in [evidence source].`

**Required structure**: baseline query (historical window) → current query (campaign window) → comparison (threshold).

### Archetype 2 — Frequency-based detection

For behaviours where frequency of an otherwise-normal event indicates compromise.

**Template**: `[Actor] may be performing [high-frequency activity] exceeding normal rates in [location], detectable via [time-binned aggregation] in [evidence source].`

**Required structure**: aggregate by time-bin + entity → threshold on count → context enrichment.

### Archetype 3 — Behavioural sequence

For multi-step attack chains where individual steps may be benign but the sequence is malicious.

**Template**: `[Actor] may be executing a [step1 → step2 → step3] chain in [location], detectable via temporal correlation across [evidence sources].`

**Considerations**:
- Each step independently testable.
- Time windows aligned with intelligence.
- Use stable identifiers (`ProcessUniqueId`, correlation IDs) over PIDs/connection tuples that recycle.

---

## 4. Phase 2 — Query authoring

### Behavioural decomposition

Break ABLE Behaviour into observable telemetry events:

1. **Identify the attack steps** — what happens sequentially?
2. **Map each step to a data source** — which table captures it?
3. **Write one query per observable** — avoid kitchen-sink queries.

### Pre-flight validation

Before executing:

1. **Platform dispatch** — every query has a platform tag.
2. **Column validity** — every column exists in the target platform's table/index reference.
3. **No cross-platform contamination** — each query uses only columns and syntax valid for its tagged platform.
4. **Time bounds** — every query has an explicit lookback filter appropriate to the query language (or NRT semantics, intentionally).
5. **Data gaps** — hypotheses with `HYPOTHESIS_BLOCKED` flagged, not executed.

For language-level discipline (filter ordering, operator selection, comments, FP engineering), apply `kusto-query-language` (or the relevant query-language skill).

---

## 5. Phase 3 — Execution

Per-platform runners and exit-code semantics live in platform-specific guides. The general contract:

| Outcome | Response |
|---|---|
| `SUCCESS` | Parse results → Phase 4 |
| `SYNTAX_ERROR` | Diagnose actual KQL/SPL/FQL/etc. error; fix specifically; re-execute. **Never** reduce time range to mask a syntax error |
| `QUOTA_EXCEEDED` | Stop the affected platform; mark remaining queries `NOT_EXECUTED`; continue other platforms |
| `TIMEOUT` | Simplify (regex → has, narrow time, remove joins, add early `project`). Limit retries |
| `AUTH_FAILURE` | Mark all remaining queries on that platform `NOT_EXECUTED` |

### Forensic lookback guidance

| Hunt category | Default lookback | Rationale |
|---|---|---|
| Persistence mechanisms | 90 days | Survives reboots; longer window needed |
| Lateral movement | 30 days | Active movement |
| Initial access / phishing | 14–30 days | Campaign windows |
| Active C2 beaconing | 7 days | Current-state indicator |
| Data exfiltration | 7–14 days | Recent activity, high data volume |

Override when the source intelligence specifies a campaign timeframe. Respect platform retention caps — EDR platforms typically retain 30–90 days; SIEM retention varies by configuration and licence tier. Check the relevant platform skill for exact limits.

---

## 6. Phase 4 — Result interpretation

### Classification

For each query returning results:

1. Apply documented FP filters (`false_positive_scenarios` / `triage_guidance`).
2. Classify each result:

| Classification | Criteria |
|---|---|
| TRUE_POSITIVE | Matches hypothesis behaviour + no FP explanation |
| FALSE_POSITIVE | Matches a documented FP scenario |
| NEEDS_TRIAGE | Ambiguous |

### Verdict

| Condition | Verdict |
|---|---|
| ≥ 1 confirmed TRUE_POSITIVE | `CONFIRMED` |
| All results FALSE_POSITIVE | `REFUTED` |
| Zero results, all queries succeeded | `REFUTED` |
| All queries failed | `INCONCLUSIVE` |
| Some failed, others succeeded with 0 results | `INCONCLUSIVE` |
| Quota / auth stopped execution | `NOT_EXECUTED` |

**`REFUTED` is a strong claim** — only valid when queries ran successfully **and** returned no true positives. If queries had `SYNTAX_ERROR`, the verdict is `INCONCLUSIVE`, not `REFUTED`.

### Pivot investigation (CONFIRMED only)

| Pivot | Purpose | When |
|---|---|---|
| Timeline | What happened before/after the hit (± 4 h) | Always |
| Scope | How many devices / users affected | Always |
| Lateral movement | Did activity spread | Endpoint compromise confirmed |
| Attribution | Process tree / parent chain | Unknown process detected |
| Entity correlation | Cross-table activity for the same entity | Multi-stage attack suspected |

All pivot queries carry a rationale linking them back to the original hypothesis finding.

---

## 7. Hunt → opentide content conversion

### Validated hunt → MDR (production detection)

A `VALIDATED` hunt with confirmed TPs and tuned filters becomes a candidate detection. Apply the **7-step conversion** in `detection-engineering/SKILL.md`:

1. Adjust time filter for target platform.
2. Add required output columns (entity mapping).
3. Reduce false positives based on hunt observations.
4. Test with frequency lookback.
5. Map entities.
6. Set conservative response actions.
7. Handle NRT constraints.

### Hunt findings → TVM updates

Confirmed hunts feed TVM `chaining` and `terrain` evidence. Use `opentide-threat` to lock the structured updates.

### Hunt gaps → DOM signals & data requirements

`PARTIAL_COVERAGE` and `BLIND_SPOT` outcomes drive new DOM `signals` or `data_requirements` entries. Use `opentide-objective` to author or refactor DOMs.

---

## 8. Quality gates

| Gate | Check |
|---|---|
| Specificity | Names specific actor, TTP, and target scope |
| Testability (ABLE) | All four ABLE components present |
| Source traceability | `source_references` with verbatim quotes |
| Scoring completeness | Confidence + relevance with rationale |
| Query quality | Each query meets the language-skill bar |
| Anti-pattern scan | AP-H1…AP-H5 cleared |

---

## 9. References

- `kusto-query-language/references/Hypothesis-Anti-Patterns.md` (AP-H1–H5).
- `detection-engineering/` for hunt-to-rule conversion (7-step process).
- Platform skills for query authoring and table references: `microsoft-sentinel/`, `microsoft-defender-endpoint/`, `splunk-spl-processing/`, `crowdstrike-falcon/`, `carbon-black-cloud/`, `sentinelone-singularity/`, `harfanglab/`.
- opentide content skills: `opentide-threat/`, `opentide-objective/`, `opentide-rule/`.
- `mitre-attack/` for technique selection and coverage analysis.
