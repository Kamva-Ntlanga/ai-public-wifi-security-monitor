
import os
from flask import Flask, jsonify, request, render_template

from config import Config
from detection.engine import NetworkDetectionEngine
from monitoring.service import NetworkSecuritySystem
from monitoring.replay import TrafficReplay

app = Flask(__name__)
app.config.from_object(Config)

security_system = None
replay_engine = None
model_loaded = False

try:
    engine = NetworkDetectionEngine(Config.MODEL_PATH)
    engine.load_model()

    security_system = NetworkSecuritySystem(engine)

    replay_engine = TrafficReplay(
        security_system,
        dataset_path="data/KDDTrain+.txt",
        interval=1.0
    )

    model_loaded = True
    print("AI model loaded successfully.")

except FileNotFoundError:
    print("AI model or dataset not available.")

except Exception as error:
    print("Application initialisation error:", error)


# MAIN SECURITY DASHBOARD
@app.route("/")
def home():
    return render_template("index.html")


# PUBLIC WI-FI CONNECTION PORTAL
@app.route("/wifi")
def wifi_portal():
    return render_template("wifi_portal.html")


# SYSTEM HEALTH
@app.route("/api/health")
def health():
    return jsonify({
        "application": "running",
        "model_loaded": model_loaded,
        "replay_available": replay_engine is not None
    })


# MONITORING STATISTICS
@app.route("/api/stats")
def stats():
    if security_system is None:
        return jsonify({"error": "AI model not loaded"}), 503

    return jsonify(security_system.get_monitoring_data())


# TRAFFIC HISTORY
@app.route("/api/traffic")
def traffic():
    if security_system is None:
        return jsonify({"error": "AI model not loaded"}), 503

    classification = request.args.get("classification")
    protocol = request.args.get("protocol")

    records = security_system.get_history()

    if classification:
        records = [
            r for r in records
            if r["classification"] == classification
        ]

    if protocol:
        records = [
            r for r in records
            if r["protocol"] == protocol
        ]

    return jsonify(records[-100:])


# SECURITY ALERTS
@app.route("/api/alerts")
def alerts():
    if security_system is None:
        return jsonify({"error": "AI model not loaded"}), 503

    return jsonify(security_system.get_alerts())


# MANUAL TRAFFIC ANALYSIS
@app.route("/api/analyse", methods=["POST"])
def analyse():
    if security_system is None:
        return jsonify({"error": "AI model not loaded"}), 503

    traffic_record = request.get_json(silent=True)

    if not isinstance(traffic_record, dict):
        return jsonify({
            "error": "A JSON traffic record is required"
        }), 400

    required_features = NetworkDetectionEngine.feature_names

    missing = [
        feature for feature in required_features
        if feature not in traffic_record
    ]

    if missing:
        return jsonify({
            "error": "Traffic record is incomplete",
            "missing_features": missing
        }), 400

    try:
        result = security_system.analyse_traffic(traffic_record)
        return jsonify(result)

    except Exception as error:
        return jsonify({"error": str(error)}), 400


# START TRAFFIC REPLAY
@app.route("/api/replay/start", methods=["POST"])
def start_replay():
    if replay_engine is None:
        return jsonify({"error": "Replay engine unavailable"}), 503

    try:
        return jsonify(replay_engine.start())
    except Exception as error:
        return jsonify({"error": str(error)}), 500


# PAUSE TRAFFIC REPLAY
@app.route("/api/replay/pause", methods=["POST"])
def pause_replay():
    if replay_engine is None:
        return jsonify({"error": "Replay engine unavailable"}), 503

    return jsonify(replay_engine.pause())


# STOP TRAFFIC REPLAY
@app.route("/api/replay/stop", methods=["POST"])
def stop_replay():
    if replay_engine is None:
        return jsonify({"error": "Replay engine unavailable"}), 503

    return jsonify(replay_engine.stop())


# REPLAY STATUS
@app.route("/api/replay/status")
def replay_status():
    if replay_engine is None:
        return jsonify({"error": "Replay engine unavailable"}), 503

    return jsonify(replay_engine.get_status())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
