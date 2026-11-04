
from datetime import datetime, timedelta
import random
import uuid
import pandas as pd


class NetworkLabSimulator:

    def __init__(self, dataset_path="data/KDDTrain+.txt"):
        self.dataset_path = dataset_path
        self.packet_history = []
        self.flow_history = []

        self.dataset = pd.read_csv(
            dataset_path,
            header=None
        )

        self.feature_names = [
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

        self.dataset[41] = (
            self.dataset[41]
            .astype(str)
            .str.strip()
            .str.replace(".", "", regex=False)
        )

        self.scenarios = {
            "normal_browsing": {
                "name": "Normal Web Browsing",
                "labels": ["normal"]
            },
            "normal_download": {
                "name": "Normal File Download",
                "labels": ["normal"]
            },
            "normal_dns": {
                "name": "Normal DNS Request",
                "labels": ["normal"]
            },
            "port_scan": {
                "name": "Port Scanning Simulation",
                "labels": ["ipsweep", "portsweep", "nmap"]
            },
            "syn_flood": {
                "name": "SYN Flood Simulation",
                "labels": ["neptune", "smurf", "pod"]
            },
            "repeated_requests": {
                "name": "Repeated Network Requests",
                "labels": ["back", "neptune"]
            },
            "mitm_simulation": {
                "name": "Man-in-the-Middle Simulation",
                "labels": ["normal"]
            },
            "password_attack": {
                "name": "Password Guessing Simulation",
                "labels": ["guess_passwd"]
            }
        }

    def generate_packets(self, scenario, username, session_id):

        if scenario not in self.scenarios:
            raise ValueError("Unknown network scenario.")

        profile = self.scenarios[scenario]
        packet_count = random.randint(5, 10)

        if scenario in [
            "port_scan", "syn_flood",
            "repeated_requests", "password_attack"
        ]:
            packet_count = random.randint(15, 25)

        source_ip = (
            "192.168.10.250"
            if scenario in [
                "port_scan", "syn_flood",
                "repeated_requests", "password_attack",
                "mitm_simulation"
            ]
            else "192.168.10.101"
        )

        packets = []
        current_time = datetime.now()

        for i in range(packet_count):

            packet = {
                "packet_id": str(uuid.uuid4())[:8],
                "timestamp": (
                    current_time + timedelta(milliseconds=i * 100)
                ).isoformat(),
                "source_ip": source_ip,
                "destination_ip": "192.168.10.1",
                "source_port": random.randint(49152, 65535),
                "destination_port": random.choice([53, 80, 443]),
                "protocol": "SIMULATED",
                "packet_size": random.randint(60, 1500),
                "username": username,
                "session_id": session_id,
                "scenario": scenario,
                "scenario_name": profile["name"],
                "capture_type": "SIMULATED"
            }

            packets.append(packet)
            self.packet_history.append(packet)

        return packets

    def extract_features(self, scenario):

        if scenario not in self.scenarios:
            raise ValueError("Unknown network scenario.")

        labels = self.scenarios[scenario]["labels"]

        matching = self.dataset[
            self.dataset[41].isin(labels)
        ]

        if matching.empty:
            raise ValueError(
                f"No benchmark records found for {scenario}"
            )

        selected = matching.sample(n=1).iloc[0]

        features = {
            name: selected[index]
            for index, name in enumerate(self.feature_names)
        }

        self.flow_history.append({
            "scenario": scenario,
            "benchmark_label": selected[41],
            "features": features.copy()
        })

        return features

    def get_packet_history(self):
        return self.packet_history

    def get_scenarios(self):
        return self.scenarios
