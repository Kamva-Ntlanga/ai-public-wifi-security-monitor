
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
            f"Expected 43 columns, received {dataset.shape[1]}"
        )

    traffic = dataset.iloc[:, :41].copy()
    traffic.columns = FEATURE_NAMES

    labels = (
        dataset.iloc[:, 41]
        .astype(str)
        .str.strip()
        .str.rstrip(".")
        .str.lower()
    )

    traffic["actual_label"] = (
        labels != "normal"
    ).astype(int)

    print("Dataset loaded successfully.")
    print("Total records:", len(traffic))
    print("Normal records:", (traffic["actual_label"] == 0).sum())
    print("Attack records:", (traffic["actual_label"] == 1).sum())

    return traffic
