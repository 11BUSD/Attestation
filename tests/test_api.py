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

    graph = client.get(f"/missions/{mission_id}/graph")
    assert graph.status_code == 200
    assert any(edge["relationship"] == "AUTHORIZED" for edge in graph.json()["relationships"])
    assert any(node["type"] == "Event" for node in graph.json()["nodes"])

    replay = client.get(f"/missions/{mission_id}/replay", params={"human_intervention": True})
    assert replay.status_code == 200
    assert len(replay.json()["timeline"]) == 1

    risk = client.get(f"/missions/{mission_id}/risk")
    assert risk.status_code == 200
    assert risk.json()["level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


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
