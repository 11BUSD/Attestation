from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _create_mission() -> str:
    response = client.post(
        "/missions",
        json={
            "objective": "Fix authentication vulnerability",
            "authorized_by": "security-lead",
            "actor_id": "factory-agent-1",
            "actor_type": "AUTONOMOUS_AGENT",
            "context": {"repo": "11BUSD/Attestation"},
        },
    )
    assert response.status_code == 200
    return response.json()["mission_id"]


def test_mission_lifecycle_endpoints():
    mission_id = _create_mission()

    event = client.post(
        f"/missions/{mission_id}/events",
        json={
            "actor_id": "factory-agent-1",
            "actor_type": "AUTONOMOUS_AGENT",
            "action": "AUTHORIZATION_GRANTED",
            "resource": "mission",
            "resource_type": "Mission",
            "source": "github",
            "policy_decision": "ALLOW",
        },
    )
    assert event.status_code == 200
    assert event.json()["integrity_hash"]

    evidence = client.post(
        f"/missions/{mission_id}/evidence",
        json={
            "type": "security scan",
            "source": "ci",
            "content": "scan report content",
            "related_events": [event.json()["event_id"]],
            "collector": "attest-ingest",
            "verification_status": "VERIFIED",
        },
    )
    assert evidence.status_code == 200
    evidence_id = evidence.json()["evidence_id"]

    claim = client.post(
        f"/missions/{mission_id}/verify",
        json={
            "claim": "Authentication vulnerability fixed",
            "evidence_ids": [evidence_id],
            "independent_checks_passed": True,
        },
    )
    assert claim.status_code == 200
    assert claim.json()["verification_state"] == "INDEPENDENTLY_VERIFIED"

    passport = client.get(f"/missions/{mission_id}/passport")
    assert passport.status_code == 200
    body = passport.json()
    assert "Evidence Coverage" in body
    assert "Unverified Claims" in body


def test_graph_replay_and_risk():
    mission_id = _create_mission()

    client.post(
        f"/missions/{mission_id}/events",
        json={
            "actor_id": "factory-agent-1",
            "actor_type": "AUTONOMOUS_AGENT",
            "action": "TOOL_INVOKED",
            "resource": "pytest",
            "resource_type": "Tool",
            "source": "runner",
            "policy_decision": "ALLOW",
            "metadata": {"result": "ok"},
        },
    )
    client.post(
        f"/missions/{mission_id}/events",
        json={
            "actor_id": "human-approver",
            "actor_type": "HUMAN",
            "action": "HUMAN_APPROVAL",
            "resource": "deployment-checkpoint",
            "resource_type": "Checkpoint",
            "source": "ui",
            "policy_decision": "ALLOW",
        },
    )
    client.post(
        f"/missions/{mission_id}/events",
        json={
            "actor_id": "factory-agent-1",
            "actor_type": "AUTONOMOUS_AGENT",
            "action": "ROLLBACK",
            "resource": "deploy-rollback",
            "resource_type": "Deployment",
            "source": "runner",
            "policy_decision": "ALLOW",
        },
    )

    graph = client.get(f"/missions/{mission_id}/graph")
    assert graph.status_code == 200
    assert any(edge["relationship"] == "AUTHORIZED" for edge in graph.json()["relationships"])
    assert any(node["type"] == "Event" for node in graph.json()["nodes"])
    human_edges = [
        edge for edge in graph.json()["relationships"] if edge["from"] == "human-approver" and edge["relationship"] == "INITIATED"
    ]
    assert len(human_edges) == 1

    replay = client.get(f"/missions/{mission_id}/replay", params={"human_intervention": True})
    assert replay.status_code == 200
    assert len(replay.json()["timeline"]) == 1
    actor_replay = client.get(f"/missions/{mission_id}/replay", params={"actor_id": "human-approver"})
    assert actor_replay.status_code == 200
    assert len(actor_replay.json()["timeline"]) == 1

    risk = client.get(f"/missions/{mission_id}/risk")
    assert risk.status_code == 200
    assert risk.json()["level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert risk.json()["dimensions"]["reversibility"] == "LOW"


def test_event_payload_mission_mismatch_is_rejected():
    mission_id = _create_mission()
    other_id = _create_mission()
    response = client.post(
        f"/missions/{mission_id}/events",
        json={
            "mission_id": other_id,
            "actor_id": "factory-agent-1",
            "actor_type": "AUTONOMOUS_AGENT",
            "action": "CONTEXT_LOADED",
            "resource": "mission-context",
            "resource_type": "Context",
            "source": "ingest",
        },
    )
    assert response.status_code == 400


def test_evidence_related_events_must_belong_to_same_mission():
    mission_id = _create_mission()
    other_id = _create_mission()
    other_event = client.post(
        f"/missions/{other_id}/events",
        json={
            "actor_id": "factory-agent-1",
            "actor_type": "AUTONOMOUS_AGENT",
            "action": "TOOL_INVOKED",
            "resource": "pytest",
            "resource_type": "Tool",
            "source": "runner",
        },
    )
    assert other_event.status_code == 200

    evidence = client.post(
        f"/missions/{mission_id}/evidence",
        json={
            "type": "tool result",
            "source": "runner",
            "content": "tool-output",
            "related_events": [other_event.json()["event_id"]],
            "collector": "attest-ingest",
        },
    )
    assert evidence.status_code == 400


def test_verify_rejects_unknown_evidence_ids():
    mission_id = _create_mission()
    response = client.post(
        f"/missions/{mission_id}/verify",
        json={
            "claim": "Authentication vulnerability fixed",
            "evidence_ids": ["missing-evidence-id"],
            "independent_checks_passed": True,
        },
    )
    assert response.status_code == 400


def test_unverified_evidence_cannot_be_independently_verified():
    mission_id = _create_mission()
    event = client.post(
        f"/missions/{mission_id}/events",
        json={
            "actor_id": "factory-agent-1",
            "actor_type": "AUTONOMOUS_AGENT",
            "action": "SECURITY_SCAN",
            "resource": "scan",
            "resource_type": "Security",
            "source": "ci",
        },
    )
    evidence = client.post(
        f"/missions/{mission_id}/evidence",
        json={
            "type": "security scan",
            "source": "ci",
            "content": "scan output",
            "related_events": [event.json()["event_id"]],
            "collector": "attest-ingest",
            "verification_status": "UNVERIFIED",
        },
    )
    claim = client.post(
        f"/missions/{mission_id}/verify",
        json={
            "claim": "security issue fixed",
            "evidence_ids": [evidence.json()["evidence_id"]],
            "independent_checks_passed": True,
        },
    )
    assert claim.status_code == 200
    assert claim.json()["verification_state"] == "EVIDENCE_SUPPORTED"
