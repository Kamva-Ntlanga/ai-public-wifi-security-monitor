from datetime import datetime


class AlertManager:

    def __init__(self):
        self.alerts = []

    def check_record(self, record):

        if record["classification"] == "Suspicious":

            alert = {
                "alert_id": len(self.alerts) + 1,
                "timestamp": datetime.now().isoformat(),
                "severity": self.get_severity(
                    record["detection_score"]
                ),
                "classification": record["classification"],
                "protocol": record["protocol"],
                "service": record["service"],
                "detection_score": record["detection_score"],
                "status": "Open"
            }

            self.alerts.append(alert)
            return alert

        return None

    def get_severity(self, score):

        if score >= 90:
            return "High"
        elif score >= 70:
            return "Medium"
        else:
            return "Low"

    def get_alerts(self):
        return self.alerts

    def update_status(self, alert_id, status):

        for alert in self.alerts:
            if alert["alert_id"] == alert_id:
                alert["status"] = status
                return True

        return False
