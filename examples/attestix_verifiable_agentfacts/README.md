# Verifiable AgentFacts with Attestix

AgentFacts reserves `certification` and `evaluations` (`auditTrail`, `auditorID`)
for trust, but the format ships no way to **prove** them. Today they are plain
strings any publisher can write anything into. A consumer reading
`certification.level: "EU-AI-Act-Annex-III"` has no way to tell a real audit from
a self-asserted claim.

This example uses [Attestix](https://github.com/VibeTensor/attestix) (Apache-2.0)
to make those fields **cryptographically verifiable**:

1. Attestix issues an Ed25519-signed W3C Verifiable Credential about the agent.
2. The AgentFacts `certification` / `evaluations` fields are populated **from**
   that credential, and the credential travels with the doc under
   `x-attestix-credential` (extra top-level properties are allowed by the schema).
3. Anyone can verify **offline**, with no call back to the issuer, that the
   credential's signature is valid *and* that the visible `certification` fields
   match exactly what was signed. A publisher cannot upgrade their own
   `certification.level` without it being detected.

## Run

```bash
pip install attestix==0.4.1rc2 jsonschema
python verifiable_agentfacts.py
```

Expected output:

```
[PASS] AgentFacts validates against agentfacts_schema.json
  [PASS] credential signature valid
  [PASS] credential is about this agent
  [PASS] certification.level matches signed claim
  [PASS] certification.issuer matches signer
  [PASS] evaluations.auditorID matches signer
  [PASS] evaluations.auditTrail points to the credential
  [PASS] forged certification.level is REJECTED offline
wrote agent.agentfacts.json
```

## How the fields map

| AgentFacts field | Filled with |
|---|---|
| `certification.level` / `issuer` / dates | the signed credential's claim, issuer DID, validity window |
| `evaluations.auditorID` | the Attestix issuer DID (who attests) |
| `evaluations.auditTrail` | the credential id (pointer to the verifiable evidence) |
| `x-attestix-credential` | the full signed credential, so verification is offline |

`agent.agentfacts.json` is a sample output. Tamper with any `certification` value
in it and re-run, and the offline check fails.
