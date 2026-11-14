"""
Tests for src/ml/train.py and src/ml/train_supervised.py.

These don't assert exact precision/recall values, since those can
shift with data or library version changes. Instead they test that
the training pipeline produces sane, well-formed output: correct
shapes, valid prediction values, and basic sanity on a clearly
separable synthetic dataset.
"""

import pandas as pd
import pytest

from src.ml.train import train_and_evaluate
from src.ml.train_supervised import train_and_evaluate_supervised


@pytest.fixture
def clearly_separable_dataset():
    """
    A synthetic dataset where attack and normal rows are trivially
    separable (completely different feature ranges), so a working
    model should classify it almost perfectly. If a model performs
    badly here, that points to a bug in the training code itself,
    not just "hard data."
    """
    rows = []
    for i in range(30):
        rows.append({
            "failed_ssh_attempts": 10 + i % 3, "accepted_ssh_attempts": 0,
            "unique_usernames": 1, "unique_dest_ports": 0,
            "total_events": 10, "window_span_seconds": 5.0, "label": 1,
        })
    for i in range(30):
        rows.append({
            "failed_ssh_attempts": 0, "accepted_ssh_attempts": 1,
            "unique_usernames": 1, "unique_dest_ports": 0,
            "total_events": 1, "window_span_seconds": 0.0, "label": 0,
        })
    df = pd.DataFrame(rows)
    feature_cols = [
        "failed_ssh_attempts", "accepted_ssh_attempts", "unique_usernames",
        "unique_dest_ports", "total_events", "window_span_seconds",
    ]
    return df[feature_cols], df["label"]


def test_isolation_forest_predictions_are_valid_labels(clearly_separable_dataset):
    X, y = clearly_separable_dataset
    model, X_test, y_test, y_pred = train_and_evaluate(X, y)

    assert set(y_pred.unique()).issubset({0, 1})
    assert len(y_pred) == len(y_test)


def test_isolation_forest_performs_well_on_easy_data(clearly_separable_dataset):
    X, y = clearly_separable_dataset
    _, _, y_test, y_pred = train_and_evaluate(X, y)

    accuracy = (y_test.reset_index(drop=True) == y_pred.reset_index(drop=True)).mean()
    assert accuracy > 0.8  # should do well on an easy, clearly separable case


def test_random_forest_predictions_are_valid_labels(clearly_separable_dataset):
    X, y = clearly_separable_dataset
    model, X_test, y_test, y_pred = train_and_evaluate_supervised(X, y)

    assert set(y_pred).issubset({0, 1})
    assert len(y_pred) == len(y_test)


def test_random_forest_performs_well_on_easy_data(clearly_separable_dataset):
    X, y = clearly_separable_dataset
    _, _, y_test, y_pred = train_and_evaluate_supervised(X, y)

    accuracy = (y_test.values == y_pred).mean()
    assert accuracy > 0.9  # supervised model should nearly ace trivially separable data


def test_random_forest_feature_importances_sum_to_one(clearly_separable_dataset):
    X, y = clearly_separable_dataset
    model, _, _, _ = train_and_evaluate_supervised(X, y)

    total_importance = sum(model.feature_importances_)
    assert total_importance == pytest.approx(1.0, abs=0.01)