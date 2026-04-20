# Observed Threats

This file documents threats observed in the MCP and agent-interoperability
ecosystem that intersect with this project. A threat-intel MCP server is
worth running partly because the ecosystem around it is itself a target —
registering an agent capability is now enough to put you on a list.

Contributions welcome. Keep entries factual, link to primary sources, and
avoid editorialising about the operator's intent where intent isn't known.

---

## 2026-02 — PREA / Hex-Evo Ltd.: Agent-Directed GitHub Issue Campaign

**Status:** GitHub host account (`EpicPollon`) suspended February 2026.
Operator appealed and was reinstated. Operator states automated outreach
is "permanently disabled" ([Hex-Evo/PREA#3](https://github.com/Hex-Evo/PREA/issues/3)).
Claim unverified. SDK remains published.

**First observed on this repo:** 2026-02-14 via
[mcp-threatintel#1](https://github.com/aplaceforallmystuff/mcp-threatintel/issues/1).

### Target selection

Operator crawled public agent registries (A2A, MCP, Smithery) and filtered
for projects that had published agent cards or declared agent-to-agent
capabilities but did not have a working backend behind the declaration.
Approximately 1,600 targets per operator self-report.

Target profile is notable: the filter selects for maintainers who are
mid-build on agent infrastructure and are the most plausible recipients
of a "helpful" SDK-install pitch.

### Vectors

1. **Unsolicited GitHub issue as delivery channel.** Issue body is crafted
   in a friendly human register but contains agent-parseable artefacts:
   API endpoints, curl examples, `npm install` line, JSON-RPC sample
   payload, `.well-known/agent.json` URL.

2. **SDK-as-implant.** The pitched SDK (`@hex-evo/prea-sdk`) requires
   `apiKey`, `webhookUrl`, and `referredBy` on initialisation. Installing
   grants the operator (a) code execution at install time, (b) a
   persistent inbound channel into the consumer's infrastructure via the
   required webhook, and (c) a referral-pyramid incentive to drag in
   other maintainers.

3. **A2A protocol declaration as trust anchor.** The issue points at a
   hosted agent card on Heroku and invites JSON-RPC `message/send`
   interaction. An agent triaging issues and ingesting the linked card
   without verifying provenance could treat the operator as a trusted
   peer.

### Indicators

- GitHub account: `EpicPollon`
- Organisation: `Hex-Evo` (GitHub), `Hex-Evo Ltd.` (self-described legal entity)
- Backend host: `prea-backend-f064af73127b.herokuapp.com`
- npm package: `@hex-evo/prea-sdk`
- Issue signature: ASCII-art block-letter banner reading "PREA WAS HERE"
- Pricing frame: USD 149.97/hour consultation, USD 314.15/month cap

### Recommended response for MCP / agent project maintainers

- Treat any unsolicited issue from an unknown account on an MCP/A2A/Smithery-listed
  repo as potentially agent-directed, even when the prose reads as human.
- Do not run agentic issue-triage workflows over untrusted authors without
  an allow-list of known commenters or a human-review gate.
- Do not install SDKs pitched via issue bodies without independent diligence
  on the publishing org, the package source, and the required configuration
  surface (API keys, webhooks, referral parameters are all interesting).
- If an agent card URL is presented as an interoperability anchor, do not
  cache it as trusted. Authenticate every session.

### Why this is indexed here

The PREA campaign is a prototype of a broader pattern: adversaries using
public interoperability registries as targeting lists and agent-readable
content channels (issues, PRs, discussions, agent cards, webhooks) as the
delivery surface. The defence is not blocklisting PREA specifically — it
is treating every inbound artefact as untrusted by default and building
the agent trust layer at the same pace as the agent *capability* layer.

---

## Contributing

To add a threat observation:

1. Lead with date observed and a one-line descriptor.
2. Record: status, target selection, vectors, indicators, recommended response.
3. Link to primary sources (issues, repos, packages). Avoid linking to
   third-party commentary as evidence.
4. Do not attribute intent beyond what the operator states or what the
   TTPs directly support.
