
import os
import uuid
from datetime import datetime

from flask import Flask, jsonify, request, render_template

from config import Config
from detection.engine import NetworkDetectionEngine
from monitoring.service import NetworkSecuritySystem
from monitoring.replay import TrafficReplay
from network_lab.simulator import NetworkLabSimulator


app = Flask(__name__)
app.config.from_object(Config)

security_system = None
replay_engine = None
network_lab_simulator = None
model_loaded = False

wifi_sessions = {}


ACTIVITY_TYPES = {
    "browse": {
        "name": "Browsing websites",
        "scenario": "normal_browsing"
    },
    "download": {
        "name": "Downloading a file",
        "scenario": "normal_download"
    },
    "repeated_requests": {
        "name": "Repeated network requests",
        "scenario": "repeated_requests"
    },
    "unusual_connection": {
        "name": "Unusual connection pattern",
        "scenario": "port_scan"
    }
}


# INITIALISE THE AI MODEL AND NETWORK SIMULATOR

try:
    engine = NetworkDetectionEngine(Config.MODEL_PATH)
    engine.load_model()

    security_system = NetworkSecuritySystem(engine)

    network_lab_simulator = NetworkLabSimulator(
        dataset_path="data/KDDTrain+.txt"
    )

    replay_engine = TrafficReplay(
        security_system,
        dataset_path="data/KDDTrain+.txt",
        interval=1.0
    )

    model_loaded = True

    print("AI model loaded successfully.")
    print("Network laboratory simulator loaded successfully.")

except Exception as error:
    print("Application initialisation error:", error)


# MAIN APPLICATION PAGES

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/wifi")
def wifi_portal():
    return render_template("wifi_portal.html")


@app.route("/activity")
def activity_page():
    return render_template("activity.html")


# SYSTEM HEALTH

@app.route("/api/health")
def health():
    return jsonify({
        "application": "running",
        "model_loaded": model_loaded,
        "replay_available": replay_engine is not None,
        "network_simulator_available": (
            network_lab_simulator is not None
        )
    })


# SIMULATED WI-FI CONNECTION

@app.route("/api/wifi/connect", methods=["POST"])
def wifi_connect():

    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()

    if not username:
        return jsonify({
            "success": False,
            "error": "Please enter a username or guest name."
        }), 400

    if len(username) > 60:
        return jsonify({
            "success": False,
            "error": "Username must not exceed 60 characters."
        }), 400

    session_id = str(uuid.uuid4())

    wifi_sessions[session_id] = {
        "session_id": session_id,
        "username": username,
        "connected_at": datetime.now().isoformat(),
        "status": "Connected"
    }

    return jsonify({
        "success": True,
        "message": "Simulated Wi-Fi connection successful.",
        "session": wifi_sessions[session_id],
        "next_page": "/activity?session_id=" + session_id
    })


@app.route("/api/wifi/session/<session_id>")
def wifi_session(session_id):

    session = wifi_sessions.get(session_id)

    if session is None:
        return jsonify({
            "success": False,
            "error": "Wi-Fi session not found."
        }), 404

    return jsonify({
        "success": True,
        "session": session
    })


# GENERATE SIMULATED NETWORK ACTIVITY AND RUN AI ANALYSIS

@app.route("/api/activity/generate", methods=["POST"])
def generate_activity():

    if security_system is None:
        return jsonify({
            "success": False,
            "error": "AI model not loaded."
        }), 503

    if network_lab_simulator is None:
        return jsonify({
            "success": False,
            "error": "Network simulator unavailable."
        }), 503

    data = request.get_json(silent=True) or {}

    session_id = data.get("session_id")
    activity_type = data.get("activity")

    session = wifi_sessions.get(session_id)

    if session is None:
        return jsonify({
            "success": False,
            "error": "Please connect to the simulated Wi-Fi first."
        }), 401

    if session.get("status") == "Blocked (simulated)":
        return jsonify({
            "success": False,
            "error": "This simulated Wi-Fi session has been blocked."
        }), 403

    if activity_type not in ACTIVITY_TYPES:
        return jsonify({
            "success": False,
            "error": "Invalid activity selected."
        }), 400

    try:

        activity = ACTIVITY_TYPES[activity_type]
        scenario = activity["scenario"]

        # STEP 1: GENERATE SIMULATED PACKET EVENTS

        packet_events = network_lab_simulator.generate_packets(
            scenario=scenario,
            username=session["username"],
            session_id=session_id
        )

        analysis_id = str(uuid.uuid4())

        for packet in packet_events:
            packet["analysis_id"] = analysis_id

        # STEP 2: SELECT A REPRESENTATIVE NSL-KDD RECORD

        traffic_record = network_lab_simulator.extract_features(
            scenario
        )

        benchmark_record = (
            network_lab_simulator.flow_history[-1]["benchmark_label"]
        )

        benchmark_class = (
            "Normal" if benchmark_record == "normal"
            else "Attack"
        )

        # STEP 3: ANALYSE THE RECORD USING THE TRAINED AI MODEL

        result = security_system.analyse_traffic(
            traffic_record
        )

        traffic_result = result["traffic"]

        # STEP 4: ATTACH SESSION AND SIMULATION INFORMATION

        metadata = {
            "analysis_id": analysis_id,
            "username": session["username"],
            "session_id": session_id,
            "activity": activity["name"],
            "scenario": scenario,
            "benchmark_label": benchmark_class,
            "benchmark_record": benchmark_record,
            "packet_count": len(packet_events),
            "capture_type": "SIMULATED"
        }

        if traffic_result["classification"] == "Suspicious":
            session["status"] = "Flagged"
        elif session.get("status") != "Blocked (simulated)":
            session["status"] = "Connected"

        metadata["session_status"] = session["status"]
        traffic_result.update(metadata)

        # UPDATE MONITORING HISTORY

        if security_system.history.records:
            security_system.history.records[-1].update(metadata)

        if security_system.processor.processed_records:
            security_system.processor.processed_records[-1].update(
                metadata
            )

        # UPDATE SECURITY ALERT IF GENERATED

        if result["alert"]:
            result["alert"].update(metadata)

        # STEP 5: RETURN THE COMPLETE ACTIVITY RESULT

        return jsonify({
            "success": True,
            "analysis_id": analysis_id,
            "activity": activity["name"],
            "scenario": scenario,
            "benchmark_label": benchmark_class,
            "benchmark_record": benchmark_record,
            "packet_count": len(packet_events),
            "capture_type": "SIMULATED",
            "packet_events": packet_events,
            "traffic": traffic_result,
            "alert": result["alert"],
            "message": (
                "Simulated network activity generated and "
                "analysed by the AI model."
            )
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# SIMULATED SESSION BLOCKING

@app.route("/api/session/block", methods=["POST"])
def block_session():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")

    session = wifi_sessions.get(session_id)

    if session is None:
        return jsonify({
            "success": False,
            "error": "Session not found."
        }), 404

    if session.get("status") == "Blocked (simulated)":
        return jsonify({
            "success": True,
            "message": "Session is already blocked."
        })

    session["status"] = "Blocked (simulated)"
    session["blocked_at"] = __import__("datetime").datetime.now().isoformat()

    for alert in security_system.get_alerts():
        if alert.get("session_id") == session_id:
            alert["status"] = "Blocked (simulated)"

    for record in security_system.history.records:
        if record.get("session_id") == session_id:
            record["session_status"] = "Blocked (simulated)"

    for record in security_system.processor.processed_records:
        if record.get("session_id") == session_id:
            record["session_status"] = "Blocked (simulated)"

    return jsonify({
        "success": True,
        "message": "Simulated session blocked successfully.",
        "session_id": session_id,
        "status": session["status"]
    })


# SIMULATED PACKET EVENT HISTORY

@app.route("/api/packets")
def packets():

    if network_lab_simulator is None:
        return jsonify({
            "error": "Network simulator unavailable."
        }), 503

    return jsonify(
        network_lab_simulator.get_packet_history()[-100:]
    )


# MONITORING STATISTICS

@app.route("/api/stats")
def stats():

    if security_system is None:
        return jsonify({
            "error": "AI model not loaded"
        }), 503

    guest_records = [
        record for record in security_system.history.records
        if record.get("session_id")
    ]

    guest_alerts = [
        alert for alert in security_system.get_alerts()
        if alert.get("session_id")
    ]

    return jsonify({
        "total_records": len(guest_records),
        "normal": sum(
            record["classification"] == "Normal"
            for record in guest_records
        ),
        "suspicious": sum(
            record["classification"] == "Suspicious"
            for record in guest_records
        ),
        "alerts": len(guest_alerts),
        "blocked_sessions": sum(
            session.get("status") == "Blocked (simulated)"
            for session in wifi_sessions.values()
        ),
        "active_sessions": sum(
            session.get("status") != "Blocked (simulated)"
            for session in wifi_sessions.values()
        )
    })


# TRAFFIC HISTORY

@app.route("/api/traffic")
def traffic():

    if security_system is None:
        return jsonify({
            "error": "AI model not loaded"
        }), 503

    classification = request.args.get("classification")
    protocol = request.args.get("protocol")

    records = [
        record for record in security_system.get_history()
        if record.get("session_id")
    ]

    if classification:
        records = [
            record for record in records
            if record["classification"] == classification
        ]

    if protocol:
        records = [
            record for record in records
            if record["protocol"] == protocol
        ]

    return jsonify(records[-100:])


# SECURITY ALERTS

@app.route("/api/alerts")
def alerts():

    if security_system is None:
        return jsonify({
            "error": "AI model not loaded"
        }), 503

    return jsonify(
        security_system.get_alerts()
    )


# MANUAL AI TRAFFIC ANALYSIS

@app.route("/api/analyse", methods=["POST"])
def analyse():

    if security_system is None:
        return jsonify({
            "error": "AI model not loaded"
        }), 503

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

        result = security_system.analyse_traffic(
            traffic_record
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 400


# DATASET REPLAY CONTROLS

@app.route("/api/replay/start", methods=["POST"])
def start_replay():

    if replay_engine is None:
        return jsonify({
            "error": "Replay engine unavailable"
        }), 503

    try:
        return jsonify(
            replay_engine.start()
        )

    except Exception as error:
        return jsonify({
            "error": str(error)
        }), 500


@app.route("/api/replay/pause", methods=["POST"])
def pause_replay():

    if replay_engine is None:
        return jsonify({
            "error": "Replay engine unavailable"
        }), 503

    return jsonify(
        replay_engine.pause()
    )


@app.route("/api/replay/stop", methods=["POST"])
def stop_replay():

    if replay_engine is None:
        return jsonify({
            "error": "Replay engine unavailable"
        }), 503

    return jsonify(
        replay_engine.stop()
    )


@app.route("/api/replay/status")
def replay_status():

    if replay_engine is None:
        return jsonify({
            "error": "Replay engine unavailable"
        }), 503

    return jsonify(
        replay_engine.get_status()
    )


# START APPLICATION

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
