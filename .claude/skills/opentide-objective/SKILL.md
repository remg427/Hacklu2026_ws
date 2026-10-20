---
name: opentide-objective
description: Authors opentide Detection Objective objects — decomposing a threat into discrete detection opportunities, writing signals as analyst-facing alert specifications, modelling data availability honestly, choosing a composition strategy, and linking upstream to threat vectors and downstream to detection rules. Covers signal decomposition quality, entity correlation, and anti-patterns distilled from production corpora. Resolves object structure and vocabularies from the installed engine instead of pinning fields. Use when structuring coverage intent, or before detection rules attach to an objective.
---

# opentide Detection Objective (DOM)

A DOM bridges the gap between threat modelling (TVM) and deployable detection rules (MDR). It answers: **"What signals would tell us this threat is happening, and what data do we need to detect them?"**

---

## Resolve the schema before authoring

Do not author from memory, and do not expect a field list in this skill. A
Detection Objective's structure is versioned, ships with the engine, and changes without
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
   `opentide://schemas/objective` returns the JSON Schema, resolved to the
   highest registered revision. `opentide://templates/objective` returns the
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
`opentide --json info objectives` to see what already exists before adding
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

What this skill carries is the part that does not move: when a Detection Objective is the
right object to reach for, how to decide what belongs in it, and what separates
a good one from a passable one.

For *what fields exist*, read the schema. For *is this valid*, run
`opentide validate`, or `opentide lint` for style, or the `validate_rule` and
`validation_report` MCP tools for a single object. A validator error outranks
anything written in this skill.

## Signals — the core of a DOM

Each signal represents a **distinct detection opportunity** — a specific observable that, when triggered, indicates the threat behaviour described by the parent DOM.

### What a signal has to carry

Field names, required status and allowed values come from the schema you
resolved, not from here. What matters is what each part is *for*, because a
validator cannot tell you whether you filled it in well.

- **The name is an alert title.** An analyst reads it at 3am with no context.
  "SAM database dump detected", never "Signal 1".
- **The description is the rule specification.** It is the handover to whoever
  writes the query: specific log fields, event identifiers, registry paths or
  API calls, and the tuning that will be needed. Vagueness here becomes a bad
  rule two steps later.
- **Severity is the severity an analyst should act on**, not how interesting
  the behaviour is to read about.
- **Effort is implementation cost**, and it exists so work can be sequenced. A
  trivial pattern match and a correlation pipeline are not the same investment.
- **Methodology is the detection approach**, and it constrains which platforms
  can host the signal at all.
- **Data availability is an honest statement about the estate.** Claiming
  coverage that does not exist is how an objective ends up specifying
  undetectable signals. `Unknown` is a legitimate answer; a wrong `Complete` is
  not. The repository's visibility configuration is what makes this claim
  checkable rather than an opinion — see **`opentide-visibility`**. The allowed
  log-source values here are injected into the generated schema from that
  configuration, so a source it does not declare cannot be referenced; declare
  it there and regenerate rather than working around the field.
- **Entities are what the signal correlates on.** List every one it genuinely
  pivots on, because they drive alert grouping and incident correlation
  downstream. Domain and type values are a controlled vocabulary -- read it
  rather than inventing a pair that looks reasonable.


## Signal decomposition — the most important design decision

The quality of a DOM is determined by how well it decomposes a threat into distinct, independently detectable signals.

### Decomposition principles

1. **By detection surface** — Endpoint signals, network signals, and cloud signals are separate. A web shell detection should have separate signals for HTTP-layer anomaly, host-layer file creation, and process spawning.
2. **By data dependency** — Different log sources = different signals. A signal requiring Sysmon EID 10 is separate from one requiring SecurityEvent 4688.
3. **By methodology** — Pattern matching, anomaly detection, and threshold-based detection are separate signals even if they target the same behaviour.
4. **By analyst action** — If two detections require different triage workflows, they are separate signals.

### Quality spectrum

| Quality | Pattern | Example |
|---|---|---|
| **Excellent** | 7 signals covering SAM dump, registry events, LSASS memory, shadow credentials, registry access, password reading, Kerberoasting | "Credential dumping on a local Windows endpoint" |
| **Good** | 3 signals covering device code auth, FIDO2 provisioning, and MFA bypass | "Entra ID Authentication Bypass" |
| **Mediocre** | Single signal for a broad topic that should decompose into 3+ signals | "Web Shell Attacks" — one signal mixing network, host, and process detection |
| **Bad** | Single signal with a laundry list of detection ideas crammed into one description | "Suspicious OAuth applications" |

### Signal description quality

The signal `description` is the **specification that MDR rules implement**. It must include:

- **Specific log fields** or Event IDs (e.g. `authenticationProtocol: "deviceCode"`, `EventID 4657`)
- **Registry paths**, API calls, or command patterns where applicable
- **Tuning guidance** (conditional access policies, AAGUID restrictions, threshold recommendations)
- **False positive scenarios** and how to distinguish them

---

## Composition strategies

The `composition` block models how signals relate to each other:

| Strategy | When to use |
|---|---|
| `Independent` | Each signal fires alone; no correlation needed. Most common. |
| `Synergetic` | Signals must combine for meaningful detection (e.g. credential spray + subsequent privilege escalation). |
| `Correlated` | Signals from different data sources must be correlated temporally. |

**Current gap**: Production corpora overwhelmingly use `Independent` with boilerplate descriptions. When authoring DOMs for multi-stage attacks, actively consider whether `Synergetic` or `Correlated` strategies would produce better detection outcomes.

---

## Linking DOMs to TVMs and MDRs

### Upstream: DOM -> TVM

- `objective.threats[]` contains TVM UUIDs.
- A single DOM can cover **many TVMs** (credential dumping DOM links to 14 TVMs).
- ATT&CK techniques are **inherited from TVMs** unless `objective.att&ck` explicitly overrides.

### Downstream: DOM -> MDR

- Signal UUIDs (`objective.signals[].uuid`) are referenced by MDR objects.
- The signal `description` serves as the **specification** that MDR detection rules implement.
- `detectors[]` and `examples[]` blocks bridge to existing vendor/community detections — populate these to accelerate MDR authoring.

### Type: Supportive

`type: Supportive` DOMs (e.g. "Risk Based Alerting Framework") have **no `threats` array**. They support detection infrastructure rather than covering specific threat vectors.

---

## Anti-patterns

| Anti-pattern | Fix |
|---|---|
| **Single-signal catch-all** | Decompose by detection surface, data dependency, methodology |
| **`availability: Unknown` everywhere** | Investigate data availability before authoring. `Unknown` defeats the purpose of data modelling. |
| **Boilerplate composition** | Think about whether signals should correlate. Don't copy-paste "Each signal triggers independently" without consideration. |
| **Wrong entity types** | Cloud-native detections should use `cloud::Authentication`, not `host::Process`. Match entities to the actual data domain. |
| **Empty `detectors` and `examples`** | Populate when vendor detections or community rules exist. Critical for coverage gap analysis. |
| **CDM migration artefacts** | Rethink migrated content for the DOM schema. Don't just paste old CDM text. |
| **Missing `effort` scores** | Populate the 1-10 scale. Investment planning depends on it. |
| **Description as unstructured prose** | Use the signal description as a technical spec, not a paragraph of prose. |
| **Overlapping DOM coverage** | Check existing DOMs before creating new ones. Update rather than duplicate. |

---

## Quality checklist

- [ ] `name` is a verb-noun phrase describing the detection goal.
- [ ] `objective.priority` aligns with TVM criticality.
- [ ] `objective.threats` lists all relevant TVM UUIDs (for `type: Threat`).
- [ ] Signals are decomposed by detection surface, data dependency, and methodology.
- [ ] Each signal `name` reads as an alert title an analyst would see.
- [ ] Each signal `description` includes specific log fields, Event IDs, tuning guidance.
- [ ] Each signal `severity` matches expected alert severity.
- [ ] `data.availability` is honestly assessed (not defaulting to `Unknown`).
- [ ] `data.requirements` separates data collection from data sources.
- [ ] `entities` include all entity types the signal correlates on.
- [ ] `detectors` and `examples` populated when vendor/community detections exist.
- [ ] `effort` score populated (1-10).
- [ ] `composition.strategy` is deliberate (not boilerplate `Independent`).
- [ ] No CDM migration artefacts remain.

---

## Collaboration with neighbouring skills

- Upstream **`opentide-threat`** for threat fidelity.
- Upstream **`opentide-visibility`** for what telemetry actually exists — it constrains the log sources a signal may reference, and grounds every data-availability claim.
- Downstream **`opentide-rule`** for executable bodies.
- **`mitre-attack`** for ATT&CK technique precision.
- **Platform/query skills** validate technical feasibility (`kusto-query-language`, `splunk-spl-processing`, etc.) according to tooling each signal references.
- **`windows-event-logs`** for Event ID prerequisites and audit policy requirements.
- **`entra-id`** for identity-layer signal design.
