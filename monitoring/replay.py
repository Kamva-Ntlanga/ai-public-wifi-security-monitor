
import threading
from data.loader import load_dataset
from detection.engine import NetworkDetectionEngine


class TrafficReplay:

    def __init__(self, security_system, dataset_path="data/KDDTrain+.txt",
                 interval=1.0):

        self.security_system = security_system
        self.dataset_path = dataset_path
        self.interval = interval

        self.dataset = None
        self.current_index = 0
        self.processed_count = 0

        self.running = False
        self.paused = False

        self.stop_event = threading.Event()
        self.resume_event = threading.Event()
        self.resume_event.set()

        self.thread = None

    def start(self):

        if self.thread and self.thread.is_alive():

            if self.paused:
                self.paused = False
                self.resume_event.set()

            return self.get_status()

        if self.dataset is None:
            self.dataset = load_dataset(self.dataset_path)

        if self.current_index >= len(self.dataset):
            self.current_index = 0
            self.processed_count = 0

        self.stop_event.clear()
        self.resume_event.set()
        self.paused = False
        self.running = True

        self.thread = threading.Thread(
            target=self._process_traffic,
            daemon=True
        )

        self.thread.start()

        return self.get_status()

    def _process_traffic(self):

        feature_names = NetworkDetectionEngine.feature_names

        try:
            while not self.stop_event.is_set():

                self.resume_event.wait()

                if self.stop_event.is_set():
                    break

                if self.current_index >= len(self.dataset):
                    break

                row = self.dataset.iloc[self.current_index]

                traffic_record = {
                    feature: row[feature]
                    for feature in feature_names
                }

                self.security_system.analyse_traffic(
                    traffic_record
                )

                self.current_index += 1
                self.processed_count += 1

                if self.stop_event.wait(self.interval):
                    break

        finally:
            self.running = False
            self.paused = False

    def pause(self):

        if self.running:
            self.paused = True
            self.resume_event.clear()

        return self.get_status()

    def stop(self):

        self.stop_event.set()
        self.resume_event.set()

        self.running = False
        self.paused = False

        return self.get_status()

    def get_status(self):

        total = len(self.dataset) if self.dataset is not None else 0

        return {
            "running": self.running,
            "paused": self.paused,
            "processed": self.processed_count,
            "total": total,
            "progress": round(
                (self.processed_count / total) * 100, 2
            ) if total else 0
        }
