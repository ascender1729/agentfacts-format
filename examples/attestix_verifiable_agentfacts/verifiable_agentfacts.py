#!/usr/bin/env python3
"""Make a NANDA AgentFacts document whose trust fields are cryptographically verifiable.

AgentFacts reserves `certification` and `evaluations` (auditTrail, auditorID) but
ships no mechanism to PROVE them - they are plain strings any publisher can write
anything into. This example uses Attestix (https://github.com/VibeTensor/attestix,
Apache-2.0) to issue a signed W3C Verifiable Credential for the agent and BIND it
to those fields, so anyone can verify the certification offline and detect tampering.

What it does:
  1. Attestix issues an Ed25519-signed conformity credential for the agent.
  2. Builds a schema-conformant AgentFacts doc, filling `certification` /
     `evaluations` FROM the signed credential, and carries the credential itself
     under `x-attestix-credential` (extra properties are allowed by the schema).
  3. Validates against agentfacts_schema.json.
  4. Verifies offline: the credential's signature is checked AND the visible
     certification fields are confirmed to match exactly what was signed - so a
     publisher cannot upgrade their own `certification.level` without detection.

Run:
    pip install attestix==0.4.1rc2 jsonschema
    python verifiable_agentfacts.py
"""
import copy
import json
from pathlib import Path

from attestix.services.credential_service import CredentialService
from jsonschema import validate

SCHEMA = Path(__file__).resolve().parents[2] / "agentfacts_schema.json"
OUT = Path(__file__).resolve().parent / "agent.agentfacts.json"
AGENT_ID = "did:web:pay.vibetensor.com"


def build_verifiable_agentfacts() -> dict:
    svc = CredentialService()

    # 1. Attestix issues a signed conformity credential about this agent.
    vc = svc.issue_credential(
        agent_id=AGENT_ID,
        credential_type="ConformityAssessmentCredential",
        issuer_name="VibeTensor Conformity (NB-0482)",
        claims={"level": "EU-AI-Act-Annex-III", "riskTier": "high"},
        expiry_days=365,
    )

    # 2. AgentFacts doc - trust fields are populated FROM the signed credential.
    return {
        "id": AGENT_ID,
        "agent_name": "urn:agent:vibetensor:pay-bot",
        "label": "Pay Bot",
        "description": "Payment-orchestration agent with verifiable EU AI Act conformity.",
        "version": "1.0.0",
        "provider": {"name": "VibeTensor", "url": "https://vibetensor.com"},
        "endpoints": {"static": ["https://pay.vibetensor.com/a2a"]},
        "capabilities": {
            "modalities": ["text"],
            "authentication": {"methods": ["bearer"]},
        },
        "skills": [{
            "id": "orchestrate-payment",
            "description": "Plan and execute a multi-step payment workflow.",
            "inputModes": ["text"],
            "outputModes": ["text"],
        }],
        "certification": {
            "level": vc["credentialSubject"]["level"],
            "issuer": vc["issuer"]["id"],
            "issuanceDate": vc["issuanceDate"],
            "expirationDate": vc["expirationDate"],
        },
        "evaluations": {
            "performanceScore": 0.98,
            "availability90d": "99.95%",
            "lastAudited": vc["issuanceDate"],
            "auditTrail": vc["id"],            # pointer to the verifiable evidence
            "auditorID": vc["issuer"]["id"],   # who attests it (the Attestix issuer DID)
        },
        # Extra props are allowed by the schema: carry the proof so verification
        # is fully offline - no call back to the issuer required.
        "x-attestix-credential": vc,
    }


def verify_offline(facts: dict):
    """Re-check a published AgentFacts doc with nothing but the doc itself."""
    svc = CredentialService()
    vc = facts.get("x-attestix-credential")
    if not vc:
        return False, {"has_attestix_credential": False}
    sig = svc.verify_credential_external(vc)
    checks = {
        "credential signature valid": sig["valid"],
        "credential is about this agent": vc["credentialSubject"]["id"] == facts["id"],
        "certification.level matches signed claim": facts["certification"]["level"] == vc["credentialSubject"]["level"],
        "certification.issuer matches signer": facts["certification"]["issuer"] == vc["issuer"]["id"],
        "certification dates match the credential": (
            facts["certification"]["issuanceDate"] == vc["issuanceDate"]
            and facts["certification"]["expirationDate"] == vc["expirationDate"]
        ),
        "evaluations.auditorID matches signer": facts["evaluations"]["auditorID"] == vc["issuer"]["id"],
        "evaluations.auditTrail points to the credential": facts["evaluations"]["auditTrail"] == vc["id"],
    }
    return all(checks.values()), checks


def main():
    facts = build_verifiable_agentfacts()

    validate(facts, json.loads(SCHEMA.read_text()))
    print("[PASS] AgentFacts validates against agentfacts_schema.json")

    ok, checks = verify_offline(facts)
    for name, passed in checks.items():
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")

    # Adversarial: publisher forges fields without re-signing the credential.
    forgeries = {
        "certification.level": lambda f: f["certification"].__setitem__("level", "EU-AI-Act-unconditional"),
        "certification.expirationDate": lambda f: f["certification"].__setitem__("expirationDate", "2099-01-01T00:00:00+00:00"),
    }
    all_forgeries_caught = True
    for field, forge in forgeries.items():
        bad = copy.deepcopy(facts)
        forge(bad)
        caught = not verify_offline(bad)[0]
        all_forgeries_caught &= caught
        print(f"  [{'PASS' if caught else 'FAIL'}] forged {field} is REJECTED offline")

    OUT.write_text(json.dumps(facts, indent=2))
    print(f"wrote {OUT.name}  (issuer/auditor DID: {facts['evaluations']['auditorID']})")

    import sys
    sys.exit(0 if ok and all_forgeries_caught else 1)


if __name__ == "__main__":
    main()
