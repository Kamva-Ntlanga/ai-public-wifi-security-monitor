from datetime import datetime


class MonitoringHistory:

    def __init__(self, max_records=1000):
        self.records = []
        self.max_records = max_records

    def add_record(self, record):

        entry = record.copy()
        entry["processed_at"] = datetime.now().isoformat()

        self.records.append(entry)

        if len(self.records) > self.max_records:
            self.records.pop(0)

        return entry

    def get_records(self, classification=None, protocol=None):

        results = self.records

        if classification:
            results = [
                r for r in results
                if r["classification"] == classification
            ]

        if protocol:
            results = [
                r for r in results
                if r["protocol"] == protocol
            ]

        return results

    def clear_history(self):
        self.records.clear()
