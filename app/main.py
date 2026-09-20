from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


class EvidenceState(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    CONTRADICTED = "CONTRADICTED"


class VerificationState(str, Enum):
    AGENT_ASSERTED = "AGENT_ASSERTED"
    EVIDENCE_SUPPORTED = "EVIDENCE_SUPPORTED"
    INDEPENDENTLY_VERIFIED = "INDEPENDENTLY_VERIFIED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CanonicalEventAction(str, Enum):
    MISSION_CREATED = "MISSION_CREATED"
    AUTHORIZATION_GRANTED = "AUTHORIZATION_GRANTED"
    CONTEXT_LOADED = "CONTEXT_LOADED"
    AGENT_STARTED = "AGENT_STARTED"
    MODEL_INVOKED = "MODEL_INVOKED"
    TOOL_INVOKED = "TOOL_INVOKED"
    MCP_INVOKED = "MCP_INVOKED"
    FILE_READ = "FILE_READ"
    FILE_WRITTEN = "FILE_WRITTEN"
    COMMAND_EXECUTED = "COMMAND_EXECUTED"
    DATA_ACCESSED = "DATA_ACCESSED"
    POLICY_CHECK = "POLICY_CHECK"
    POLICY_BLOCK = "POLICY_BLOCK"
    POLICY_ALLOW = "POLICY_ALLOW"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    TEST_STARTED = "TEST_STARTED"
    TEST_COMPLETED = "TEST_COMPLETED"
    SECURITY_SCAN = "SECURITY_SCAN"
    COMMIT_CREATED = "COMMIT_CREATED"
    PULL_REQUEST_CREATED = "PULL_REQUEST_CREATED"
    DEPLOYMENT_STARTED = "DEPLOYMENT_STARTED"
    DEPLOYMENT_COMPLETED = "DEPLOYMENT_COMPLETED"
    ROLLBACK = "ROLLBACK"
    OBSERVATION = "OBSERVATION"
    INCIDENT = "INCIDENT"
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    MISSION_CLOSED = "MISSION_CLOSED"


class MissionCreate(BaseModel):
    objective: str = Field(min_length=1)
    authorized_by: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    actor_type: str = Field(min_length=1)
    context: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = Field(default="default")


class Mission(BaseModel):
    mission_id: str
    created_at: datetime
    objective: str
    authorized_by: str
    actor_id: str
    actor_type: str
    context: dict[str, Any]
    tenant_id: str
    status: str


class MissionEventIn(BaseModel):
    event_id: str | None = None
    mission_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: str = Field(min_length=1)
    actor_type: str = Field(min_length=1)
    action: CanonicalEventAction
    resource: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    source: str = Field(min_length=1)
    parent_event_id: str | None = None
    policy_decision: str = "UNSPECIFIED"
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MissionEvent(BaseModel):
    event_id: str
    mission_id: str
    timestamp: datetime
    actor_id: str
    actor_type: str
    action: CanonicalEventAction
    resource: str
    resource_type: str
    source: str
    parent_event_id: str | None
    policy_decision: str
    evidence_refs: list[str]
    metadata: dict[str, Any]
    integrity_hash: str


class EvidenceIn(BaseModel):
    evidence_id: str | None = None
    type: str = Field(min_length=1)
    source: str = Field(min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content: str = Field(min_length=1)
    related_events: list[str] = Field(default_factory=list)
    related_claims: list[str] = Field(default_factory=list)
    collector: str = Field(min_length=1)
    integrity_status: str = "COLLECTED"
    verification_status: str = "UNVERIFIED"


class Evidence(BaseModel):
    evidence_id: str
    type: str
    source: str
    timestamp: datetime
    content_hash: str
    related_events: list[str]
    related_claims: list[str]
    collector: str
    integrity_status: str
    verification_status: str


class VerificationRequest(BaseModel):
    claim: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    independent_checks_passed: bool = False


class ClaimRecord(BaseModel):
    claim_id: str
    claim: str
    verification_state: VerificationState
    evidence_ids: list[str]
    verification_plan: list[str]
    last_updated: datetime


class MissionStore(BaseModel):
    mission: Mission
    events: list[MissionEvent] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    claims: list[ClaimRecord] = Field(default_factory=list)


app = FastAPI(title="ATTEST", description="Independent Assurance Infrastructure for Autonomous Software")
_DB: dict[str, MissionStore] = {}


def _deterministic_hash(payload: str) -> str:
    return sha256(payload.encode("utf-8")).hexdigest()


def _build_verification_plan(claim: str) -> list[str]:
    claim_l = claim.lower()
    checks = [
        "reproduce original failure",
        "execute changed implementation",
        "run regression suite",
        "compare relevant telemetry",
    ]
    if "vulnerab" in claim_l or "security" in claim_l or "auth" in claim_l:
        checks.extend(
            [
                "reproduce original attack",
                "run targeted security tests",
                "inspect changed authorization path",
                "verify deployment state",
            ]
        )
    return checks


def _coverage(mission: MissionStore) -> dict[str, EvidenceState]:
    actions = {event.action for event in mission.events}
    types = {e.type.lower() for e in mission.evidence}

    def present(action: CanonicalEventAction) -> bool:
        return action in actions

    coverage = {
        "intent": EvidenceState.VERIFIED if mission.mission.objective else EvidenceState.MISSING,
        "authorization": EvidenceState.VERIFIED if present(CanonicalEventAction.AUTHORIZATION_GRANTED) else EvidenceState.MISSING,
        "identity": EvidenceState.VERIFIED if mission.mission.actor_id and mission.mission.actor_type else EvidenceState.MISSING,
        "context": EvidenceState.VERIFIED if present(CanonicalEventAction.CONTEXT_LOADED) else EvidenceState.PARTIAL if mission.mission.context else EvidenceState.MISSING,
        "tool provenance": EvidenceState.VERIFIED if present(CanonicalEventAction.TOOL_INVOKED) else EvidenceState.MISSING,
        "resource access": EvidenceState.VERIFIED if (present(CanonicalEventAction.FILE_READ) or present(CanonicalEventAction.DATA_ACCESSED)) else EvidenceState.MISSING,
        "action provenance": EvidenceState.VERIFIED if len(mission.events) > 0 else EvidenceState.MISSING,
        "change provenance": EvidenceState.VERIFIED if (present(CanonicalEventAction.FILE_WRITTEN) or present(CanonicalEventAction.COMMIT_CREATED)) else EvidenceState.MISSING,
        "testing": EvidenceState.VERIFIED if "test result" in types or present(CanonicalEventAction.TEST_COMPLETED) else EvidenceState.MISSING,
        "security": EvidenceState.VERIFIED if "security scan" in types or present(CanonicalEventAction.SECURITY_SCAN) else EvidenceState.MISSING,
        "deployment": EvidenceState.VERIFIED if present(CanonicalEventAction.DEPLOYMENT_COMPLETED) else EvidenceState.MISSING,
        "outcome": EvidenceState.VERIFIED if present(CanonicalEventAction.MISSION_CLOSED) else EvidenceState.PARTIAL,
        "human approval": EvidenceState.VERIFIED if present(CanonicalEventAction.HUMAN_APPROVAL) else EvidenceState.MISSING,
    }

    if present(CanonicalEventAction.POLICY_BLOCK) or present(CanonicalEventAction.INCIDENT):
        coverage["outcome"] = EvidenceState.CONTRADICTED if coverage["outcome"] == EvidenceState.VERIFIED else EvidenceState.PARTIAL

    return coverage


def _coverage_summary(coverage: dict[str, EvidenceState]) -> dict[str, Any]:
    weights = {
        EvidenceState.VERIFIED: 1.0,
        EvidenceState.PARTIAL: 0.5,
        EvidenceState.MISSING: 0.0,
        EvidenceState.CONTRADICTED: 0.0,
    }
    total = len(coverage)
    weighted = sum(weights[state] for state in coverage.values())
    return {
        "categories": coverage,
        "explainable_score": round((weighted / total) * 100, 2) if total else 0,
        "method": "weighted deterministic mapping: VERIFIED=1.0 PARTIAL=0.5 MISSING/CONTRADICTED=0.0",
    }


def _risk(mission: MissionStore) -> dict[str, Any]:
    coverage = _coverage(mission)
    unresolved_security = any(
        claim.verification_state != VerificationState.INDEPENDENTLY_VERIFIED
        and ("security" in claim.claim.lower() or "vulnerab" in claim.claim.lower() or "auth" in claim.claim.lower())
        for claim in mission.claims
    )

    dimensions: dict[str, str] = {
        "blast_radius": "MEDIUM" if any(e.action == CanonicalEventAction.DEPLOYMENT_COMPLETED for e in mission.events) else "LOW",
        "data_sensitivity": "MEDIUM" if any(e.action == CanonicalEventAction.DATA_ACCESSED for e in mission.events) else "LOW",
        "privilege": "HIGH" if any(e.action == CanonicalEventAction.COMMAND_EXECUTED for e in mission.events) else "LOW",
        "reversibility": "LOW" if any(e.action == CanonicalEventAction.ROLLBACK for e in mission.events) else "MEDIUM",
        "environment": "HIGH" if any(e.action == CanonicalEventAction.DEPLOYMENT_COMPLETED for e in mission.events) else "LOW",
        "change_size": "MEDIUM" if len([e for e in mission.events if e.action in {CanonicalEventAction.FILE_WRITTEN, CanonicalEventAction.COMMIT_CREATED}]) > 1 else "LOW",
        "dependency_impact": "LOW",
        "test_coverage": "LOW" if coverage["testing"] == EvidenceState.VERIFIED else "HIGH",
        "security_findings": "HIGH" if unresolved_security else "LOW",
        "policy_exceptions": "HIGH" if any(e.action == CanonicalEventAction.POLICY_BLOCK for e in mission.events) else "LOW",
        "historical_failure_rate": "MEDIUM",
    }

    severity_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    score = 0
    for value in dimensions.values():
        score += {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[value]

    avg = score / len(dimensions)
    overall = severity_order[min(3, int(avg - 1))]
    if dimensions["security_findings"] == "HIGH" and dimensions["environment"] == "HIGH":
        overall = RiskLevel.CRITICAL

    return {
        "level": overall,
        "dimensions": dimensions,
        "explanation": "Risk is independently calculated from mission events, evidence coverage, and verification state.",
        "evidence_refs": [e.evidence_id for e in mission.evidence],
    }


def _passport(mission: MissionStore) -> dict[str, Any]:
    coverage_summary = _coverage_summary(_coverage(mission))
    risk = _risk(mission)
    claims = [claim.model_dump() for claim in mission.claims]
    unverified = [c for c in claims if c["verification_state"] != VerificationState.INDEPENDENTLY_VERIFIED]

    return {
        "Executive Summary": f"Mission {mission.mission.mission_id} executed with independent evidence tracking.",
        "Mission Intent": mission.mission.objective,
        "Authorization": mission.mission.authorized_by,
        "Agent Identity": {"actor_id": mission.mission.actor_id, "actor_type": mission.mission.actor_type},
        "Model Information": {"status": "Captured via MODEL_INVOKED events"},
        "Context": mission.mission.context,
        "Tools": [e.resource for e in mission.events if e.action == CanonicalEventAction.TOOL_INVOKED],
        "MCP": [e.resource for e in mission.events if e.action == CanonicalEventAction.MCP_INVOKED],
        "Resources": [{"resource": e.resource, "resource_type": e.resource_type} for e in mission.events],
        "Actions": [e.model_dump() for e in mission.events],
        "Policy Decisions": [{"event_id": e.event_id, "decision": e.policy_decision} for e in mission.events if "POLICY" in e.action.value],
        "Changes": [e.model_dump() for e in mission.events if e.action in {CanonicalEventAction.FILE_WRITTEN, CanonicalEventAction.COMMIT_CREATED, CanonicalEventAction.PULL_REQUEST_CREATED}],
        "Testing": [x.model_dump() for x in mission.evidence if x.type.lower() == "test result"],
        "Security": [x.model_dump() for x in mission.evidence if x.type.lower() == "security scan"],
        "Deployment": [e.model_dump() for e in mission.events if "DEPLOYMENT" in e.action.value],
        "Post-Deployment Observations": [e.model_dump() for e in mission.events if e.action == CanonicalEventAction.OBSERVATION],
        "Verification": claims,
        "Exceptions": [e.model_dump() for e in mission.events if e.action in {CanonicalEventAction.POLICY_BLOCK, CanonicalEventAction.INCIDENT}],
        "Human Approvals": [e.model_dump() for e in mission.events if e.action == CanonicalEventAction.HUMAN_APPROVAL],
        "Evidence Coverage": coverage_summary,
        "Unverified Claims": unverified,
        "Final Status": {
            "mission_status": mission.mission.status,
            "risk": risk["level"],
            "verification_complete": len(unverified) == 0,
        },
    }


@app.post("/missions", response_model=Mission)
def create_mission(payload: MissionCreate) -> Mission:
    mission_id = str(uuid4())
    mission = Mission(
        mission_id=mission_id,
        created_at=datetime.now(timezone.utc),
        objective=payload.objective,
        authorized_by=payload.authorized_by,
        actor_id=payload.actor_id,
        actor_type=payload.actor_type,
        context=payload.context,
        tenant_id=payload.tenant_id,
        status="OPEN",
    )
    _DB[mission_id] = MissionStore(mission=mission)
    return mission


@app.get("/missions/{mission_id}", response_model=Mission)
def get_mission(mission_id: str) -> Mission:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")
    return store.mission


@app.post("/missions/{mission_id}/events", response_model=MissionEvent)
def add_event(mission_id: str, payload: MissionEventIn) -> MissionEvent:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")

    event_id = payload.event_id or str(uuid4())
    if payload.mission_id and payload.mission_id != mission_id:
        raise HTTPException(status_code=400, detail="Path mission_id does not match payload mission_id")
    normalized_mission_id = mission_id
    event = MissionEvent(
        event_id=event_id,
        mission_id=normalized_mission_id,
        timestamp=payload.timestamp,
        actor_id=payload.actor_id,
        actor_type=payload.actor_type,
        action=payload.action,
        resource=payload.resource,
        resource_type=payload.resource_type,
        source=payload.source,
        parent_event_id=payload.parent_event_id,
        policy_decision=payload.policy_decision,
        evidence_refs=payload.evidence_refs,
        metadata=payload.metadata,
        integrity_hash=_deterministic_hash(f"{event_id}|{normalized_mission_id}|{payload.timestamp.isoformat()}|{payload.action.value}|{payload.resource}|{payload.source}"),
    )
    store.events.append(event)
    if event.action == CanonicalEventAction.MISSION_CLOSED:
        store.mission.status = "CLOSED"
    return event


@app.post("/missions/{mission_id}/evidence", response_model=Evidence)
def add_evidence(mission_id: str, payload: EvidenceIn) -> Evidence:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")
    valid_event_ids = {event.event_id for event in store.events}
    unknown_event_refs = [event_id for event_id in payload.related_events if event_id not in valid_event_ids]
    if unknown_event_refs:
        raise HTTPException(status_code=400, detail=f"Unknown related_events for mission: {unknown_event_refs}")

    evidence = Evidence(
        evidence_id=payload.evidence_id or str(uuid4()),
        type=payload.type,
        source=payload.source,
        timestamp=payload.timestamp,
        content_hash=_deterministic_hash(payload.content),
        related_events=payload.related_events,
        related_claims=payload.related_claims,
        collector=payload.collector,
        integrity_status=payload.integrity_status,
        verification_status=payload.verification_status,
    )
    store.evidence.append(evidence)
    return evidence


@app.get("/missions/{mission_id}/evidence", response_model=list[Evidence])
def list_evidence(mission_id: str) -> list[Evidence]:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")
    return store.evidence


@app.get("/missions/{mission_id}/graph")
def mission_graph(mission_id: str) -> dict[str, Any]:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")

    nodes_by_id: dict[str, dict[str, str]] = {
        f"human:{store.mission.authorized_by}": {"id": store.mission.authorized_by, "type": "Human"},
        f"actor:{store.mission.actor_id}": {"id": store.mission.actor_id, "type": "Agent"},
        f"mission:{store.mission.mission_id}": {"id": store.mission.mission_id, "type": "Mission"},
    }
    edges = [
        {"from": store.mission.authorized_by, "to": store.mission.mission_id, "relationship": "AUTHORIZED"},
        {"from": store.mission.actor_id, "to": store.mission.mission_id, "relationship": "INITIATED"},
    ]

    action_relationship_map = {
        CanonicalEventAction.FILE_READ: "READ",
        CanonicalEventAction.FILE_WRITTEN: "WROTE",
        CanonicalEventAction.TOOL_INVOKED: "CALLED",
        CanonicalEventAction.MCP_INVOKED: "CALLED",
        CanonicalEventAction.COMMAND_EXECUTED: "CALLED",
    }

    for event in store.events:
        nodes_by_id[f"actor:{event.actor_id}"] = {"id": event.actor_id, "type": event.actor_type}
        nodes_by_id[f"event:{event.event_id}"] = {"id": event.event_id, "type": "Event"}
        nodes_by_id[f"resource:{event.resource}"] = {"id": event.resource, "type": event.resource_type}
        edges.append({"from": event.actor_id, "to": event.event_id, "relationship": "INITIATED"})
        edges.append(
            {
                "from": event.event_id,
                "to": event.resource,
                "relationship": action_relationship_map.get(event.action, "USED"),
            }
        )

    for evidence in store.evidence:
        nodes_by_id[evidence.evidence_id] = {"id": evidence.evidence_id, "type": "Evidence"}
        for ref in evidence.related_events:
            edges.append({"from": ref, "to": evidence.evidence_id, "relationship": "SUPPORTED_BY"})

    return {"mission_id": mission_id, "nodes": list(nodes_by_id.values()), "relationships": edges}


@app.get("/missions/{mission_id}/passport")
def mission_passport(mission_id: str) -> dict[str, Any]:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")
    return _passport(store)


@app.get("/missions/{mission_id}/replay")
def mission_replay(
    mission_id: str,
    actor_id: str | None = None,
    tool: str | None = None,
    resource: str | None = None,
    policy: str | None = None,
    risk: str | None = None,
    human_intervention: bool | None = None,
) -> dict[str, Any]:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")

    items = sorted(store.events, key=lambda x: x.timestamp)
    if actor_id:
        items = [x for x in items if x.actor_id == actor_id]
    if tool:
        items = [x for x in items if x.action == CanonicalEventAction.TOOL_INVOKED and x.resource == tool]
    if resource:
        items = [x for x in items if x.resource == resource]
    if policy:
        items = [x for x in items if x.policy_decision == policy]
    if human_intervention:
        items = [x for x in items if x.action == CanonicalEventAction.HUMAN_APPROVAL]
    mission_risk = _risk(store)["level"]
    if risk:
        if mission_risk != risk.upper():
            items = []

    return {
        "mission_id": mission_id,
        "mission_risk": mission_risk,
        "risk_filter_scope": "mission",
        "timeline": [
            {
                "timestamp": x.timestamp,
                "actor": x.actor_id,
                "action": x.action,
                "resource": x.resource,
                "policy_decision": x.policy_decision,
                "evidence": x.evidence_refs,
                "result": x.metadata.get("result", "recorded"),
            }
            for x in items
        ],
    }


@app.post("/missions/{mission_id}/verify")
def verify_claim(mission_id: str, payload: VerificationRequest) -> ClaimRecord:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")

    referenced_evidence = {e.evidence_id for e in store.evidence}
    unknown_evidence = [eid for eid in payload.evidence_ids if eid not in referenced_evidence]
    if unknown_evidence:
        raise HTTPException(status_code=400, detail=f"Unknown evidence_ids for mission: {unknown_evidence}")
    evidence_ids = list(payload.evidence_ids)
    evidence_map = {e.evidence_id: e for e in store.evidence}
    acceptable_evidence_status = {"VERIFIED"}
    all_evidence_verified = all(
        evidence_map[eid].verification_status.upper() in acceptable_evidence_status for eid in evidence_ids
    ) if evidence_ids else False
    state = VerificationState.AGENT_ASSERTED
    if evidence_ids:
        state = VerificationState.EVIDENCE_SUPPORTED
    if evidence_ids and payload.independent_checks_passed and all_evidence_verified:
        state = VerificationState.INDEPENDENTLY_VERIFIED

    claim = ClaimRecord(
        claim_id=str(uuid4()),
        claim=payload.claim,
        verification_state=state,
        evidence_ids=evidence_ids,
        verification_plan=_build_verification_plan(payload.claim),
        last_updated=datetime.now(timezone.utc),
    )
    store.claims.append(claim)
    return claim


@app.get("/missions/{mission_id}/risk")
def mission_risk(mission_id: str) -> dict[str, Any]:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")
    return _risk(store)


@app.get("/missions/{mission_id}/claims", response_model=list[ClaimRecord])
def mission_claims(mission_id: str) -> list[ClaimRecord]:
    store = _DB.get(mission_id)
    if not store:
        raise HTTPException(status_code=404, detail="Mission not found")
    return store.claims
