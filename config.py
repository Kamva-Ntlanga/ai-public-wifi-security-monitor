import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "development-key-change-before-deployment")
    DEBUG = False
    DATASET_MODE = True
    MODEL_PATH = "models/network_pipeline.pkl"
    ALERT_THRESHOLD = 70
    MAX_TRAFFIC_RECORDS = 1000
