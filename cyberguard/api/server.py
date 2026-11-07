"""
CyberGuard AI - Enterprise REST API Gateway
Provides endpoints for ingestion, manual approvals, telemetry streaming, and metrics.
"""

from flask import Blueprint, Flask, request, jsonify
from cyberguard.models.state import CyberGuardState
from cyberguard.orchestrator.graph import CyberGuardGraph
from cyberguard.learning.feedback_loop import GLOBAL_LEARNING_ENGINE

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")
orchestrator = CyberGuardGraph()

@api_bp.route("/ingest", methods=["POST"])
def ingest_telemetry():
    """Ingests raw security telemetry from firewalls, EDR, or SIEM."""
    data = request.get_json()
    if not data or "events" not in data:
        return jsonify({"error": "Missing 'events' array in payload"}), 400

    events = data["events"]
    state = CyberGuardState(raw_events=events)
    final_state = orchestrator.run(state)

    return jsonify({
        "status": "processed",
        "session_id": final_state.session_id,
        "threat_confirmed": final_state.threat_confirmed,
        "response_authorized": final_state.response_authorized,
        "actions_taken": [a.__dict__ for a in final_state.executed_actions],
        "summary": final_state.final_report_markdown
    })

@api_bp.route("/metrics", methods=["GET"])
def get_metrics():
    """Returns self-learning and detection accuracy metrics."""
    return jsonify(GLOBAL_LEARNING_ENGINE.get_performance_metrics())

def create_app():
    app = Flask(__name__)
    app.register_blueprint(api_bp)
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(port=8080)

