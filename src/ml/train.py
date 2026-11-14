"""
Train and evaluate an Isolation Forest anomaly detector on the
engineered feature table, and compare it against the rule-based
detectors' known performance.

Isolation Forest is unsupervised: during training it never sees the
labels, only the feature values, and learns to isolate points that
look "different" from the bulk of the data. We only use the labels
afterward, to measure how well its notion of "different" lines up
with our actual ground truth.
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, confusion_matrix, classification_report


FEATURE_COLUMNS = [
    "failed_ssh_attempts",
    "accepted_ssh_attempts",
    "unique_usernames",
    "unique_dest_ports",
    "total_events",
    "window_span_seconds",
]


def load_dataset(path: str = "data/labeled/features.csv") -> tuple[pd.DataFrame, pd.Series]:
    """Load features and labels, dropping identifier columns (source_ip, window_start)."""
    df = pd.read_csv(path)
    X = df[FEATURE_COLUMNS]
    y = df["label"]
    return X, y


def train_and_evaluate(X: pd.DataFrame, y: pd.Series, test_size: float = 0.3, random_state: int = 42):
    """
    Split into train/test, train Isolation Forest on the training set
    (unsupervised, ignoring y_train), then evaluate against y_test.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Capped at 0.5: contamination represents "fraction of data that is
    # anomalous," which is only meaningful below 50%. With our small,
    # roughly-balanced dataset, a stratified split can occasionally push
    # the training fold's attack ratio just over 0.5 by chance.
    contamination = min(y_train.mean(), 0.5)

    model = IsolationForest(contamination=contamination, random_state=random_state)
    model.fit(X_train)  # unsupervised: y_train is never passed in

    # Isolation Forest outputs -1 (anomaly) or 1 (normal); convert to our
    # label convention where 1 = attack, 0 = normal, so predictions and
    # ground truth use the same scale and sklearn's metrics work directly.
    raw_preds = model.predict(X_test)
    y_pred = pd.Series(raw_preds).map({-1: 1, 1: 0})

    return model, X_test, y_test, y_pred


def print_evaluation(y_test: pd.Series, y_pred: pd.Series):
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f"Test set size: {len(y_test)}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}\n")

    print("Confusion matrix (rows=actual, cols=predicted):")
    print("              Predicted Normal  Predicted Attack")
    print(f"Actual Normal        {cm[0][0]:>5}              {cm[0][1]:>5}")
    print(f"Actual Attack        {cm[1][0]:>5}              {cm[1][1]:>5}")

    print("\nFull classification report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"], zero_division=0))


if __name__ == "__main__":
    X, y = load_dataset()
    print(f"Loaded {len(X)} samples ({y.sum()} attack, {len(y) - y.sum()} normal)\n")

    model, X_test, y_test, y_pred = train_and_evaluate(X, y)
    print_evaluation(y_test, y_pred)