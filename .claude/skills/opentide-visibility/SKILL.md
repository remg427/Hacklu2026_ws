---
name: opentide-visibility
description: Models the detection estate in the opentide visibility configuration — which assets generate logs, which log sources are actually collected and on which system, and which external vendor detections already cover ground. This configuration is upstream of Detection Objectives, because the allowed values for a signal's log sources are injected into the generated schema from here, so a source that is not declared cannot be referenced. Covers honest coverage claims, the regenerate-after-change cycle, and the placeholder trap. Use when auditing or declaring log source coverage, when a signal cannot reference a log source, when data availability claims need grounding, or when onboarding a new telemetry source.
---

# opentide visibility — modelling the detection estate

Visibility is the repository's answer to **"what telemetry do we actually have?"**. Everything downstream that claims coverage is only as honest as this file.

It is a **configuration, not an object**. Threat Vectors, Detection Objectives and Detection Rules are authored content under the objects tree, each with its own schema family. Visibility is a single configuration for the repository, it has no UUID, no per-threat instances, and it changes when the *estate* changes — a new connector, a decommissioned agent, a new tenant — not when a threat does.

---

## Why this file has teeth

Visibility is not documentation. The engine reads it and feeds generated schemas from it.

**The allowed values for a Detection Objective signal's log sources are injected from this configuration.** That has two consequences people hit in the wrong order:

1. A log source that is not declared here **cannot be referenced** from an objective signal. Validation rejects it. The fix is to declare the source, not to work around the field.
2. After changing visibility you **must regenerate** (`opentide generate schemas`) or the injected enum is stale. Symptoms are a source you just added being rejected, or one you removed still being accepted. That is a stale artefact, not a validator bug.

External detectors are injected the same way, which is what lets an objective record that a vendor product already covers a signal.

So the ordering is: **declare the estate, regenerate, then author objectives against it.** Reaching for an objective first and discovering the enum does not contain your source is the common way round, and it wastes a cycle.

---

## Resolve the schema before authoring

Do not author from memory, and do not expect a field list in this skill. This configuration is versioned, it is generated from a code-first model in the engine, and it changes without this skill changing.

1. **MCP resources**, when the opentide MCP server is connected — read the schema and template resources for the visibility family the same way you would for any other, and `opentide://vocabularies/{name}` for any controlled field.
2. **Generated artefacts**, when no server is connected — `.opentide/schemas/` holds one schema file per registered revision. Take the one matching the declared revision.
3. **Generate them**, when neither exists: `opentide generate schemas`.

A schema that is an empty `{"type": "object"}` stub means generation has never run against a real configuration in this repository. That is the cause — not a missing object type, and not a reason to invent fields.

`.opentide/schemas/` is a **generated** directory and is explicitly not overridable. Never hand-edit a schema to make a value pass; change the configuration and regenerate. A hand-edit is erased by the next generation and misleads everyone until it is.

### Where it lives

The configuration is bundled with sensible defaults inside the engine and overridden in the repository's configuration directory, deep-merged on top — nested tables merge, scalars replace. Resolve the actual path from the workspace path configuration rather than assuming it; a repository may have moved its layout, and a CoreTide-era corpus has not been migrated yet.

### A note on the prose docs

The engine's narrative docs and glossary describe visibility as controlling "which objects are exposed/deployed in a given context". The model declares assets, log sources and external detectors — a telemetry estate model. When the prose and the generated schema disagree, **the schema wins**. Read it before acting on either.

---

## What each part is for

Field names, required status and allowed values come from the schema you resolved. What a validator cannot check is whether you filled them in *honestly*, which is the whole point of this file.

### Log sources — the required core

A log source is a stream you **actually collect today**, not one you could collect, intend to collect, or believe is probably on.

- **Name it the way the rest of the repository will refer to it.** This name becomes the value objectives use. Renaming it later invalidates every signal that referenced it, so spend a moment on it now.
- **The system matters.** It binds the source to the platform that holds it, and platform identifiers match exactly — a near-miss silently binds nothing.
- **Tie it to the assets it comes from** where the model allows. A source with no asset relationship cannot answer "which part of the estate goes dark if this breaks?"
- **Tenancy is not decoration.** In a multi-tenant estate, a source present in one tenant and absent in another is a partial-coverage fact that downstream availability claims depend on.
- **References earn trust.** A link to the connector runbook or onboarding ticket is what lets a reviewer confirm the source is real without asking you.

### Assets — what generates the telemetry

Assets are the estate itself: the systems, platforms and services producing logs.

- **Criticality here is business impact**, not log volume and not how interesting the asset is to attackers. It is what makes a coverage gap rankable.
- **Describe the asset, not its logging.** The logging relationship belongs to the log source.
- **Keep the surface consistent with the vocabulary** the engine already uses for threat surfaces, so estate and threat modelling can be compared instead of merely coexisting.

### External detectors — what is already covered

Detectors record vendor or third-party detections that already catch something.

- **This is the build-or-not decision.** A signal already covered by a licensed product that nobody checked is how teams build a detection they already own.
- **Name the technology** so the entry is actionable rather than a vague claim of coverage.
- **"Covered" is not binary.** A vendor detection that fires only on default configuration, or only on one platform, is partial coverage — say so in the description rather than implying completeness.

---

## Honest coverage is the deliverable

The only failure mode that matters here is a configuration that *looks* complete.

A declared log source nobody collects makes every downstream availability claim false while passing validation. An objective then specifies signals that cannot be detected, a rule gets written against a table with no data, and the gap surfaces during an incident instead of during review.

When you do not know whether a source is collected, say so and go and find out. Unknown is a legitimate, recoverable state; a confident wrong answer is neither.

Two questions worth asking of any entry before you commit it:

- **Could I prove this is collected right now?** A table that returns rows, a connector that reports healthy, a runbook that says it was onboarded. If not, it is a plan, not visibility.
- **Would an analyst at 3am agree with this?** They are the one who discovers that "Complete" meant "we bought the licence".

---

## Anti-patterns

| Anti-pattern | Why it is wrong |
|---|---|
| Leaving the bundled placeholder log source in place | The shipped default exists to make a fresh repository valid, not to describe anything. It validates cleanly and describes nothing, which is the worst combination. |
| Declaring a source so an objective will validate | Inverts the dependency. The configuration exists to constrain objectives; editing it to satisfy one launders a false coverage claim into the repository. |
| Hand-editing a generated schema | Generated artefacts are not overridable, the edit is erased on the next generation, and until then it hides a real mismatch. |
| Changing visibility and not regenerating | The injected enum goes stale, then the next person debugs a validator that is reporting the truth about an old artefact. |
| Treating visibility as per-threat work | It is estate-level. Touching it during threat modelling means it drifts to whatever the current threat needed. |
| Aspirational availability | "Partial" and "Unknown" are usable by a reviewer. A wrong "Complete" is not detectable by any tool. |
| Asset entries that restate the log source | Duplicated meaning, two places to update, and they will disagree. |

---

## Quality checklist

- [ ] Every declared log source is genuinely collected today, and I could show evidence
- [ ] The bundled placeholder entry is gone
- [ ] Each log source names the system that holds it, matching the platform identifier exactly
- [ ] Log sources are tied to the assets that produce them, where the model supports it
- [ ] Multi-tenant gaps are recorded rather than averaged away
- [ ] Asset criticality reflects business impact, not log volume
- [ ] External detectors state their technology and the limits of their coverage
- [ ] Schemas regenerated after the change, and the repository validates
- [ ] No generated schema was hand-edited
- [ ] Names are ones the repository can live with, since objectives will reference them

---

## Collaboration with neighbouring skills

| Situation | Skill |
|---|---|
| A signal's data availability or log sources need grounding | `opentide-objective` — this configuration is what makes those claims checkable |
| A signal cannot reference a log source | Declare it here and regenerate, then return to `opentide-objective` |
| Deciding whether to build a detection at all | Check external detectors here first, then `opentide-rule` |
| Which platform actually holds a source, and what it can do | The platform skill for that vendor, plus the engine's platform list |
| Threat surface vocabulary alignment | `opentide-threat` — estate surface and threat surface should be comparable |
| Where this sits in the object lifecycle | `detection-engineering` for the cross-object view |

Visibility is upstream of all three object families. When coverage is contested, this file is the evidence — so it is worth more care than its size suggests.
