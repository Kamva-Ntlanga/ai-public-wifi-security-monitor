class TrafficProcessor:

    def __init__(self, detection_engine):
        self.detection_engine = detection_engine
        self.processed_records = []

    def process_record(self, traffic_record):

        result = self.detection_engine.analyse(traffic_record)

        record = {
            "classification": result["classification"],
            "detection_score": result["detection_score"],
            "protocol": traffic_record["protocol_type"],
            "service": traffic_record["service"],
            "flag": traffic_record["flag"]
        }

        self.processed_records.append(record)

        return record

    def get_processed_records(self):
        return self.processed_records
