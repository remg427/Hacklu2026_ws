---
name: opentide-threat
description: Converts threat intelligence into opentide Threat Vector objects — source hygiene, atomising reports into discrete adversary behaviours, gap analysis before modelling, then schema-backed YAML authoring. Covers terrain as preconditions rather than narrative, chaining between vectors, ATT&CK mapping, actor attribution, structured descriptions, and anti-patterns distilled from production corpora. Resolves object structure, vocabularies and repository layout from the installed engine instead of pinning fields. Use when turning reports, feeds or narratives into threat vectors, or refactoring existing ones, before detection objectives exist.
---

# opentide Threat Vector (TVM)

## Why one skill handles both "intel" and "YAML"

Splitting "TI analysis" and "TVM authoring" into sibling skills creates ambiguous triggers. Threat Vector work is fundamentally **intel -> structured hypothesis -> validated YAML** — keep upstream triage inside this skill under **Phase A**, then transition to **Phase B**. One deliverable lineage from intelligence intake to a validated threat vector object.

---

## Phase A — Intelligence structuring

Skip or shorten Phase A only when the user already has a definitive TVM brief or edits to an existing file.

### Workflow

1. **Source hygiene** — Producer, publication date, TLP/risk markings. Treat rumours and unsourced summaries as lowest trust.
2. **Facts versus inference** — Quote or summarise only substantiated statements; label guesses explicitly.
3. **Atomisation** — Split composite reporting into observable procedures (installer ran, DLL loaded, C2 beacon, credential access, persistence). One primary behaviour candidate per bullet for TVM scoping.
4. **ATT&CK mapping** — Map only where behaviour is clear; annotate low-confidence mappings. Use sub-techniques when the specific implementation is documented. See `mitre-attack` skill.
5. **Gap checklist** — What is unknown (privilege achieved, tooling version, infra). Open questions block careless TVMs.
6. **Source credibility assessment** — Vendor reports (high), OSINT (medium), CTI feeds (variable), rumour mill (lowest). Rate explicitly.
7. **IOC hygiene** — Expiration dates, TLP markings, attribution caveats. IOCs without provenance are noise.

### Structured hand-off

```markdown
## Intelligence summary
[Brief factual summary, British English]

## Atomised behaviours
| # | Observable | Evidence cite | ATT&CK | Confidence |
|---|-------------|---------------|---------|-------------|
| 1 | ... | ... | ... | high/med/low |

## Gaps before modelling
- ...
```

Guardrails: no fabrication of sightings, IOCs, or attribution beyond the evidence supplied.

---

## Phase B — TVM YAML authoring

### Resolve the schema before authoring

Do not author from memory, and do not expect a field list in this skill. A
Threat Vector's structure is versioned, ships with the engine, and changes without
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
   `opentide://schemas/threat` returns the JSON Schema, resolved to the
   highest registered revision. `opentide://templates/threat` returns the
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
`opentide --json info threats` to see what already exists before adding
something that overlaps.

Repository layout is not fixed either. A CoreTide-era corpus uses different
family names and directories than a current one, and `opentide migrate objects`
is what moves it forward -- the repository owner's decision, not one to take
mid-task. Derive paths from the template you just resolved rather than assuming
either layout.

### Why there is no field table here

Required and optional status, enum members, controlled vocabularies and
deprecations all move with the schema revision. A copy of them here would go
stale without anything failing loudly, which is worse than having no copy at
all.

What this skill carries is the part that does not move: when a Threat Vector is the
right object to reach for, how to decide what belongs in it, and what separates
a good one from a passable one.

For *what fields exist*, read the schema. For *is this valid*, run
`opentide validate`, or `opentide lint` for style, or the `validate_rule` and
`validation_report` MCP tools for a single object. A validator error outranks
anything written in this skill.

### Terrain — the most misunderstood field

Terrain answers: **"What environmental conditions, access levels, or configurations must exist for this threat to be realised?"**

It is NOT a description of the attack. It is NOT a summary of the intelligence.

#### Quality spectrum

| Quality | Example | Why |
|---|---|---|
| **Excellent** | "Attackers need to have gained administrative privileges in the organization's network, and with access to the AD FS server itself. The target services need to trust the federation." | Specifies: required privilege, access target, trust relationship |
| **Good** | "Application with SSO login requiring MFA, with legacy authentication (local login) not disabled." | Specifies: configuration state, specific misconfiguration |
| **Good** | "Affected version: Apache Log4j2 2.0-beta9 through 2.15.0. Excluding security releases: 2.12.2, 2.12.3, and 2.3.1" | Specifies: exact version range with exclusions |
| **Mediocre** | "A threat actor needs initial access to move laterally through the network." | Too generic — what kind of access? What network? |
| **Bad** | "attacker needs to entice users to download payload and to open it." | Restates the attack, not preconditions |

#### Terrain authoring rules

1. State **privilege level** required (admin, user, unauthenticated, specific role)
2. State **access scope** (network segment, specific server, cloud tenant, internet-facing)
3. State **configuration prerequisites** (feature enabled, policy misconfigured, version range)
4. State **trust relationships** that must exist (federation, SSO, delegation, certificate chain)
5. 1-4 sentences. Concise. Do NOT restate the description.

---

### Chaining — linking TVMs

Chaining models relationships between TVMs using a controlled vocabulary:

| Category | Relation | Meaning |
|---|---|---|
| **sequence** | `sequence::preceeds` | Target TVM occurs AFTER this TVM |
| **sequence** | `sequence::succeeds` | Target TVM occurs BEFORE this TVM |
| **atomicity** | `atomicity::implements` | This TVM is a specific implementation of the target |
| **atomicity** | `atomicity::implemented` | Target TVM is a specific implementation of this TVM |
| **support** | `support::enabling` | Target TVM enables this TVM |
| **support** | `support::enabled` | This TVM enables the target |
| **support** | `support::synergize` | Bidirectional support |

#### Chaining rules

1. The `vector` field contains the **UUID** of the target TVM, always annotated with `# TVM Name`.
2. Include a `description` narrative explaining the relationship.
3. Verify the target TVM exists in the corpus before adding a chain.
4. Multiple chains per TVM are normal (2-3 typical for complex threats).

```yaml
chaining:
  - relation: sequence::succeeds
    vector: 1a68b5eb-0112-424d-a21f-88dda0b6b8df #Spearphishing Link
    description: |
      Phishing emails were sent to victims using an invite to a dinner
      reception bearing a logo from the CDU...
  - relation: atomicity::implements
    vector: 4a807ac4-xxxx-xxxx-xxxx-xxxxxxxxxxxx #MFA Bypass Techniques
    description: |
      This phishing kit is a specific implementation of MFA bypass
      using adversary-in-the-middle session proxying.
```

---

### Description — structured prose

Use YAML `|` block scalar with markdown headings for longer descriptions:

```yaml
description: |
  ## Attack Flow
  The adversary sends spearphishing emails containing...

  ## Impact
  Successful exploitation grants...

  ## Evasion Techniques
  The kit employs...

  ## References
  See ref [1] for the original analysis and ref [2, 3] for
  related campaign reporting.
```

Cross-reference sources using `ref [1]`, `ref [a]`, `ref [2, 3]` notation matching the `references` block.

---

### Actor attribution

```yaml
actors:
  - name: att&ck::G0016 #[Enterprise] APT29, Blue Kitsune, Cozy Bear, The Dukes
  - name: misp::2ee5ed7a-c4d0-40be-a837-20817474a15b #UNC2452, DarkHalo
    sighting: |
      APT29 added credentials to OAuth Applications and Service Principals
      to maintain persistent access to compromised tenants.
    references:
      - https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/
```

- Use both `att&ck::G####` and `misp::UUID` when available.
- Always add `# alias list` comment.
- Include `sighting` + `references` when specific evidence exists.

---

## Anti-patterns

| Anti-pattern | Fix |
|---|---|
| **Terrain restates description** | Terrain = preconditions; Description = what the attack does |
| **Unbounded ATT&CK mapping** (7+ techniques) | Map only techniques with clear behavioural evidence; 1-5 typical |
| **Mixed ATT&CK matrices** (Enterprise + ICS) | Separate Enterprise and ICS technique lists |
| **Dangling chaining UUIDs** | Verify target TVM exists before adding chain |
| **Commented-out template boilerplate** | Remove unused scaffolding; only comment fields you intend to populate |
| **Shotgunning leverage/impact values** | Pick 2-4 directly applicable values, not every tangential one |
| **Missing actors when known** | Always populate actors when threat groups are documented |
| **Missing chaining for obvious sequences** | Discovery TVMs should chain to privilege escalation; initial access to execution |
| **Vague one-line terrain** | Specify privilege, access scope, configuration, trust relationships |
| **Spelling/grammar errors** | Proofread — errors erode trust in the analytical product |
| **Stale schema version** | Always check the live template for the current schema version |

---

## Quality checklist

- [ ] `name` is sentence-case, action-oriented, describes the adversary behaviour.
- [ ] `criticality` is calibrated against severity + impact + sophistication.
- [ ] `metadata.schema` matches the current live template version, with `organisation` block populated.
- [ ] `metadata.uuid` is a fresh UUIDv4 (not reused from another TVM).
- [ ] `terrain` states preconditions (privilege, access, config, trust) — not a description restatement.
- [ ] `description` uses `|` block scalar with `##` headings for structure.
- [ ] `description` cross-references sources with `ref [N]` notation.
- [ ] `att&ck` uses sub-techniques when specific, with `# Technique Name` comments. 1-5 entries.
- [ ] `actors` populated with `att&ck::G####` or `misp::UUID` format when known.
- [ ] `surface` uses `Category::Subcategory::Detail` hierarchical notation.
- [ ] `leverage` and `impact` have 2-4 directly applicable values (not shotgunned).
- [ ] `chaining` references verified UUIDs with `# TVM Name` comments and `description` narratives.
- [ ] No commented-out template boilerplate remains.
- [ ] No spelling/grammar errors.
- [ ] References include at least 1 public source.

---

## Interaction with sibling skills

| Next step after TVM | Skill |
|---------------------|-------|
| Map ATT&CK techniques precisely | `mitre-attack` |
| Define detection intent / signals | `opentide-objective` |
| Implement deployable artefacts | `opentide-rule` + platform skills |

Never edit schemas, Templates, or engine configuration files unless explicitly directed.
