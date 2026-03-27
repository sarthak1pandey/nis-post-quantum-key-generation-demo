"""
model.py — Adaptive Cryptographic Mode Selector

Uses a Decision Tree classifier trained on network and system parameters
to predict the optimal cryptographic mode: Classical, PQC, or Hybrid.

Cryptographic Agility: The ability to switch between algorithms
without redesigning the entire system. The ML model enables this.
"""

import csv
import os

# Graceful import — falls back to rule-based if sklearn not installed
try:
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.preprocessing import LabelEncoder
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

DATASET_PATH = 'dataset.csv'


def generate_dataset(filepath=DATASET_PATH, n_samples=100):
    """
    Generates a synthetic training dataset if the CSV file is missing.

    Feature columns:
      latency_ms       — Network round-trip latency (ms)
      bandwidth_kbps   — Available network bandwidth
      cpu_power_score  — CPU capability (0.0 = weak, 1.0 = powerful)
      message_size_kb  — Size of the message to be encrypted
      security_level   — Required security level (1–5)
      hndl_risk        — Harvest-Now-Decrypt-Later threat score (0.0–1.0)

    Target: mode → Classical | PQC | Hybrid
    """
    import random
    random.seed(42)
    rows = []

    for _ in range(n_samples):
        latency    = round(random.uniform(5, 500), 1)
        bandwidth  = round(random.uniform(50, 10000), 0)
        cpu        = round(random.uniform(0.1, 1.0), 2)
        msg_size   = round(random.uniform(0.5, 500), 2)
        security   = random.randint(1, 5)
        hndl       = round(random.uniform(0.0, 1.0), 2)

        # Deterministic labelling rules for training clarity
        if hndl >= 0.65 or security >= 4:
            mode = 'Hybrid'
        elif hndl >= 0.35 and cpu >= 0.5:
            mode = 'PQC'
        elif cpu < 0.3 or latency > 350:
            mode = 'Classical'
        elif security >= 3 and hndl >= 0.2:
            mode = 'PQC'
        else:
            mode = 'Classical'

        rows.append([latency, bandwidth, cpu, msg_size, security, hndl, mode])

    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'latency_ms', 'bandwidth_kbps', 'cpu_power_score',
            'message_size_kb', 'security_level', 'hndl_risk', 'mode'
        ])
        writer.writerows(rows)

    return rows


class AdaptiveSelector:
    """
    ML-based adaptive mode selector.
    Trains a Decision Tree on historical crypto environment data.
    """

    def __init__(self):
        self.model   = None
        self.encoder = None
        self.trained = False

    def _load_data(self):
        """Load dataset CSV; auto-generate if missing."""
        if not os.path.exists(DATASET_PATH):
            generate_dataset()

        X, y = [], []
        with open(DATASET_PATH, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    X.append([
                        float(row['latency_ms']),
                        float(row['bandwidth_kbps']),
                        float(row['cpu_power_score']),
                        float(row['message_size_kb']),
                        float(row['security_level']),
                        float(row['hndl_risk']),
                    ])
                    y.append(row['mode'].strip())
                except (ValueError, KeyError):
                    continue
        return X, y

    def train(self):
        """Fit the Decision Tree on the loaded dataset."""
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is not installed. Run: pip install scikit-learn")

        X, y = self._load_data()
        if len(X) < 10:
            raise ValueError("Dataset too small (< 10 samples).")

        self.encoder = LabelEncoder()
        y_encoded    = self.encoder.fit_transform(y)

        self.model = DecisionTreeClassifier(
            max_depth=5,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42
        )
        self.model.fit(X, y_encoded)
        self.trained = True

    def predict(self, latency_ms, bandwidth_kbps, cpu_power_score,
                message_size_kb, security_level, hndl_risk):
        """Predict the best cryptographic mode for the given environment."""
        if not self.trained:
            self.train()

        features   = [[latency_ms, bandwidth_kbps, cpu_power_score,
                        message_size_kb, security_level, hndl_risk]]
        pred_label = self.model.predict(features)[0]
        return self.encoder.inverse_transform([pred_label])[0]

    def rule_based_predict(self, latency_ms, bandwidth_kbps, cpu_power_score,
                           message_size_kb, security_level, hndl_risk):
        """
        Pure rule-based fallback — no ML library required.
        Used when scikit-learn is unavailable.
        """
        if hndl_risk >= 0.65 or security_level >= 4:
            return 'Hybrid'
        elif hndl_risk >= 0.35 and cpu_power_score >= 0.5:
            return 'PQC'
        else:
            return 'Classical'