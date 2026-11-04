from monitoring.processor import TrafficProcessor
from monitoring.history import MonitoringHistory
from alerts.manager import AlertManager


class NetworkSecuritySystem:

    def __init__(self, detection_engine):

        self.processor = TrafficProcessor(detection_engine)
        self.history = MonitoringHistory()
        self.alert_manager = AlertManager()

    def analyse_traffic(self, traffic_record):

        result = self.processor.process_record(traffic_record)

        self.history.add_record(result)

        alert = self.alert_manager.check_record(result)

        return {
            "traffic": result,
            "alert": alert
        }

    def get_monitoring_data(self):

        return {
            "total_records": len(self.history.records),
            "normal": sum(
                r["classification"] == "Normal"
                for r in self.history.records
            ),
            "suspicious": sum(
                r["classification"] == "Suspicious"
                for r in self.history.records
            ),
            "alerts": len(self.alert_manager.get_alerts())
        }

    def get_alerts(self):
        return self.alert_manager.get_alerts()

    def get_history(self):
        return self.history.get_records()
