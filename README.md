# ATTEST

Independent assurance infrastructure for autonomous software.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## MVP API

- `POST /missions`
- `GET /missions/{mission_id}`
- `POST /missions/{mission_id}/events`
- `POST /missions/{mission_id}/evidence`
- `GET /missions/{mission_id}/evidence`
- `GET /missions/{mission_id}/graph`
- `GET /missions/{mission_id}/passport`
- `GET /missions/{mission_id}/replay`
- `POST /missions/{mission_id}/verify`
- `GET /missions/{mission_id}/risk`
- `GET /missions/{mission_id}/claims`

Replay filters:

- `actor_id`
- `tool`
- `resource`
- `policy`
- `risk` (mission-level predicate against computed mission risk)
- `human_intervention`

## Principles implemented

- Canonical mission/event/evidence schema
- Integrity hashing for events and evidence content
- Deterministic evidence coverage states (`VERIFIED`, `PARTIAL`, `MISSING`, `CONTRADICTED`)
- Claim verification states (`AGENT_ASSERTED`, `EVIDENCE_SUPPORTED`, `INDEPENDENTLY_VERIFIED`)
- Replay timeline, risk model dimensions, evidence graph projection
- Mission Passport generation with unverified-claim surfacing

LLM output is never treated as evidence; claims remain unverified until evidence and checks are attached.
