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
- `GET /missions/:id`
- `POST /missions/:id/events`
- `POST /missions/:id/evidence`
- `GET /missions/:id/evidence`
- `GET /missions/:id/graph`
- `GET /missions/:id/passport`
- `GET /missions/:id/replay`
- `POST /missions/:id/verify`
- `GET /missions/:id/risk`
- `GET /missions/:id/claims`

## Principles implemented

- Canonical mission/event/evidence schema
- Integrity hashing for events and evidence content
- Deterministic evidence coverage states (`VERIFIED`, `PARTIAL`, `MISSING`, `CONTRADICTED`)
- Claim verification states (`AGENT_ASSERTED`, `EVIDENCE_SUPPORTED`, `INDEPENDENTLY_VERIFIED`)
- Replay timeline, risk model dimensions, evidence graph projection
- Mission Passport generation with unverified-claim surfacing

LLM output is never treated as evidence; claims remain unverified until evidence and checks are attached.
