import pandas as pd


FEATURE_NAMES = [
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


def load_dataset(file_path):

    dataset = pd.read_csv(file_path, header=None)

    if dataset.shape[1] != 43:
        raise ValueError(
            "Invalid NSL-KDD dataset. Expected 43 columns."
        )

    traffic = dataset.iloc[:, :41].copy()
    traffic.columns = FEATURE_NAMES

    labels = dataset.iloc[:, 41].astype(str).str.strip()

    traffic["actual_label"] = (
        labels != "normal"
    ).astype(int)

    return traffic
