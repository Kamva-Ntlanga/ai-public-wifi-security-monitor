import joblib
import pandas as pd
import numpy as np


class NetworkDetectionEngine:

    def __init__(self, model_path):
        self.model_path = model_path
        self.model = None

    def load_model(self):
        self.model = joblib.load(self.model_path)
        return True

    def analyse(self, traffic_record):

        if self.model is None:
            raise RuntimeError("AI model has not been loaded.")

        traffic = pd.DataFrame(
            [traffic_record],
            columns=self.feature_names
        )

        prediction = self.model.predict(traffic)[0]
        probabilities = self.model.predict_proba(traffic)[0]

        return {
            "classification": (
                "Suspicious" if prediction == 1 else "Normal"
            ),
            "detection_score": round(
                float(probabilities[1] * 100), 2
            )
        }

    feature_names = [
        "duration", "protocol_type", "service", "flag",
        "src_bytes", "dst_bytes", "land", "wrong_fragment",
        "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted",
        "num_root", "num_file_creations", "num_shells",
        "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count",
        "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate",
        "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate"
    ]
