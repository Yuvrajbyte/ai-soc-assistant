"""
Supervised baseline: Random Forest, trained with access to labels
(unlike Isolation Forest, which never sees them during training).

This gives a third point of comparison alongside the rule-based
detectors and the unsupervised Isolation Forest: does having labels
to learn from meaningfully outperform a generic anomaly detector on
this same small dataset?
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, confusion_matrix, classification_report

from src.ml.train import FEATURE_COLUMNS, load_dataset


def train_and_evaluate_supervised(X: pd.DataFrame, y: pd.Series, test_size: float = 0.3, random_state: int = 42):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Unlike Isolation Forest, Random Forest DOES see y_train: it's
    # supervised, learning directly which feature patterns correspond
    # to attack vs. normal, rather than inferring "unusual" generically.
    model = RandomForestClassifier(n_estimators=100, random_state=random_state)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    return model, X_test, y_test, y_pred


def print_evaluation(y_test: pd.Series, y_pred, feature_names: list[str] = None, model=None):
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

    if model is not None and feature_names is not None:
        print("Feature importances (which features the model relied on most):")
        importances = sorted(zip(feature_names, model.feature_importances_), key=lambda x: -x[1])
        for name, importance in importances:
            print(f"  {name:<25} {importance:.3f}")


if __name__ == "__main__":
    X, y = load_dataset()
    print(f"Loaded {len(X)} samples ({y.sum()} attack, {len(y) - y.sum()} normal)\n")

    model, X_test, y_test, y_pred = train_and_evaluate_supervised(X, y)
    print_evaluation(y_test, y_pred, feature_names=FEATURE_COLUMNS, model=model)