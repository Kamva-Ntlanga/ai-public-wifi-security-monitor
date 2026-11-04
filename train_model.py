
import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from data.loader import load_dataset


DATASET_PATH = "data/KDDTrain+.txt"
MODEL_PATH = "models/network_pipeline.pkl"

def train():

    print("Loading network traffic dataset...")

    dataset = load_dataset(DATASET_PATH)

    X = dataset.drop(columns=["actual_label"])
    y = dataset["actual_label"]

    categorical_features = [
        "protocol_type",
        "service",
        "flag"
    ]

    numerical_features = [
        column for column in X.columns
        if column not in categorical_features
    ]

    preprocessing = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                categorical_features
            ),
            (
                "numerical",
                "passthrough",
                numerical_features
            )
        ]
    )

    pipeline = Pipeline([
        ("preprocessing", preprocessing),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight="balanced",
                n_jobs=-1
            )
        )
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print("Training Random Forest model...")

    pipeline.fit(X_train, y_train)

    predictions = pipeline.predict(X_test)

    print("\nMODEL EVALUATION")
    print("-------------------------")

    print("Accuracy:", round(
        accuracy_score(y_test, predictions) * 100, 2
    ), "%")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    print("\nClassification Report:")
    print(classification_report(y_test, predictions))

    os.makedirs("models", exist_ok=True)

    joblib.dump(pipeline, MODEL_PATH)

    print("\nModel saved successfully:", MODEL_PATH)


if __name__ == "__main__":
    train()
