import os
from flask import Flask, jsonify, request

from config import Config
from detection.engine import NetworkDetectionEngine
from monitoring.service import NetworkSecuritySystem

app = Flask(__name__)
app.config.from_object(Config)

# Initialise the AI detection system
security_system = None
model_loaded = False

try:
    engine = NetworkDetectionEngine(Config.MODEL_PATH)
    engine.load_model()

    security_system = NetworkSecuritySystem(engine)
    model_loaded = True

except FileNotFoundError:
    print("AI model not available yet. Waiting for model setup.")

except Exception as error:
    print("Model initialisation error:", error)


@app.route("/")
def home():
    return jsonify({
        "system": "AI-Based Public Wi-Fi Security Monitoring System",
        "status": "online",
        "model_loaded": model_loaded,
        "mode": "dataset demonstration"
    })


@app.route("/api/health")
def health():
    return jsonify({
        "application": "running",
        "model_loaded": model_loaded
    })


@app.route("/api/stats")
def stats():
    if security_system is None:
        return jsonify({"error": "AI model not loaded"}), 503

    return jsonify(security_system.get_monitoring_data())


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


@app.route("/api/alerts")
def alerts():
    if security_system is None:
        return jsonify({"error": "AI model not loaded"}), 503

    return jsonify(security_system.get_alerts())


@app.route("/api/analyse", methods=["POST"])
def analyse():
    if security_system is None:
        return jsonify({"error": "AI model not loaded"}), 503

    traffic_record = request.get_json(silent=True)

    if not isinstance(traffic_record, dict):
        return jsonify({"error": "A JSON traffic record is required"}), 400

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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
