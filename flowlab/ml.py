import json
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from threadpoolctl import threadpool_limits

from .config import DATA, MODELS
from .datasets import fingerprint

MODEL_NAMES = {
    "logistic": "Logistic Regression",
    "rf": "Random Forest",
    "xgboost": "XGBoost",
    "extra": "Extra Trees",
    "mlp": "MLP",
    "tabm": "TabM",
}


def signed_log(x):
    return np.sign(x) * np.log1p(np.abs(x))


class TabMClassifier(ClassifierMixin, BaseEstimator):
    def __init__(self, epochs=35, seed=42):
        self.epochs, self.seed = epochs, seed

    def fit(self, x, y):
        import tabm
        import torch

        torch.set_num_threads(4)
        torch.manual_seed(self.seed)
        self.classes_ = np.unique(y)
        self.model_ = tabm.TabM.make(
            n_num_features=x.shape[1], d_out=len(self.classes_), n_blocks=2, d_block=64, k=8, dropout=0.1
        )
        optimizer = torch.optim.AdamW(self.model_.parameters(), lr=0.002, weight_decay=0.0003)
        tx = torch.tensor(np.asarray(x), dtype=torch.float32)
        ty = torch.tensor(y, dtype=torch.long)
        weight = torch.tensor(compute_sample_weight("balanced", y), dtype=torch.float32)
        self.model_.train()
        for _ in range(self.epochs):
            for ids in torch.randperm(len(y)).split(512):
                optimizer.zero_grad()
                logits = self.model_(tx[ids])
                loss = torch.nn.functional.cross_entropy(
                    logits.flatten(0, 1), ty[ids].repeat_interleave(logits.shape[1]), reduction="none"
                )
                loss = (loss.reshape(len(ids), -1).mean(1) * weight[ids]).mean()
                loss.backward()
                optimizer.step()
        self.model_.eval()
        return self

    def predict_proba(self, x):
        import torch

        torch.set_num_threads(4)

        with torch.no_grad():
            outputs = [
                self.model_(chunk).softmax(-1).mean(1).numpy()
                for chunk in torch.tensor(np.asarray(x), dtype=torch.float32).split(2048)
            ]
        return np.concatenate(outputs)

    def predict(self, x):
        return self.classes_[self.predict_proba(x).argmax(1)]


def metrics(truth, predicted, labels=None):
    labels = sorted(set(truth) | set(predicted)) if labels is None else labels
    report = classification_report(truth, predicted, labels=labels, output_dict=True, zero_division=0)
    supported = sorted(set(truth))
    supported_report = classification_report(
        truth, predicted, labels=supported, output_dict=True, zero_division=0
    )
    report["macro avg"] = supported_report.get(
        "macro avg", {"precision": 0, "recall": 0, "f1-score": 0, "support": len(truth)}
    )
    benign = np.array(truth) == "BENIGN"
    fp = int(np.sum(benign & (np.array(predicted) != "BENIGN")))
    return {
        "macro_f1": float(f1_score(truth, predicted, labels=supported, average="macro", zero_division=0)),
        "macro_definition": "Unweighted mean over classes with ground-truth support in this partition",
        "evaluated_classes": supported,
        "accuracy": float(accuracy_score(truth, predicted)),
        "false_positive_rate": float(fp / benign.sum()) if benign.sum() else None,
        "report": report,
        "labels": list(labels),
        "confusion": [[len(truth)]]
        if len(labels) == 1
        else confusion_matrix(truth, predicted, labels=labels).tolist(),
    }


def train(dataset="fixture_completed", algorithms=None, progress=lambda _: None, seed=42):
    meta = json.loads((DATA / f"{dataset}.json").read_text())
    path = DATA / f"{dataset}.csv"
    if fingerprint(path) != meta["sha256"]:
        raise ValueError("Dataset fingerprint changed; prepare it again")
    frame = pd.read_csv(path)
    features = meta["features"]
    train_mask, valid_mask, test_mask = [frame.split == s for s in ("train", "validation", "test")]
    if any(not m.any() for m in [train_mask, valid_mask, test_mask]):
        raise ValueError("All three data splits are required")
    encoder = LabelEncoder().fit(frame.loc[train_mask, "label"])
    if len(encoder.classes_) < 2:
        raise ValueError("Training requires at least two classes")
    numeric = frame[features].replace([np.inf, -np.inf], np.nan)
    x, y = numeric.loc[train_mask], encoder.transform(frame.loc[train_mask, "label"])
    classifiers = {
        "logistic": lambda: LogisticRegression(max_iter=600, class_weight="balanced", random_state=seed),
        "rf": lambda: RandomForestClassifier(
            n_estimators=140,
            min_samples_leaf=2,
            n_jobs=4,
            class_weight="balanced_subsample",
            random_state=seed,
        ),
        "extra": lambda: ExtraTreesClassifier(
            n_estimators=140, min_samples_leaf=2, n_jobs=4, class_weight="balanced", random_state=seed
        ),
        "mlp": lambda: MLPClassifier(
            hidden_layer_sizes=(96, 48), max_iter=100, early_stopping=False, random_state=seed, batch_size=256
        ),
        "tabm": lambda: TabMClassifier(seed=seed),
    }
    from xgboost import XGBClassifier

    classifiers["xgboost"] = lambda: XGBClassifier(
        n_estimators=180,
        max_depth=5,
        learning_rate=0.07,
        n_jobs=4,
        random_state=seed,
        tree_method="hist",
        eval_metric="mlogloss",
    )
    saved = []
    for name in algorithms or list(MODEL_NAMES):
        progress(f"Training {MODEL_NAMES[name]} on {dataset}")
        start = time.perf_counter()
        pipeline = Pipeline(
            [
                ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
                ("log", FunctionTransformer(signed_log)),
                ("scale", StandardScaler()),
                ("classifier", classifiers[name]()),
            ]
        )
        kwargs = (
            {"classifier__sample_weight": compute_sample_weight("balanced", y)}
            if name in {"xgboost", "mlp"}
            else {}
        )
        with warnings.catch_warnings(record=True) as caught, threadpool_limits(limits=4):
            pipeline.fit(x, y, **kwargs)
        training_seconds = time.perf_counter() - start
        output = {}
        for split, mask in [("validation", valid_mask), ("test", test_mask)]:
            start = time.perf_counter()
            probability = pipeline.predict_proba(numeric.loc[mask])
            predicted = encoder.inverse_transform(probability.argmax(1))
            output[split] = metrics(
                frame.loc[mask, "label"].tolist(), predicted.tolist(), labels=sorted(frame.label.unique())
            )
            output[split]["inference_ms_per_flow"] = 1000 * (time.perf_counter() - start) / mask.sum()
            output[split]["unseen_classes"] = sorted(set(frame.loc[mask, "label"]) - set(encoder.classes_))
        # Select an empirical validation threshold; this is not probability calibration.
        val_probs = pipeline.predict_proba(numeric.loc[valid_mask])
        benign_col = list(encoder.classes_).index("BENIGN") if "BENIGN" in encoder.classes_ else None
        benign_scores = (
            1 - val_probs[frame.loc[valid_mask, "label"].to_numpy() == "BENIGN", benign_col]
            if benign_col is not None
            else []
        )
        threshold = max(0.9, float(np.quantile(benign_scores, 0.99))) if len(benign_scores) else 0.99
        model_id = f"{dataset}--{name}"
        metadata = {
            "id": model_id,
            "name": MODEL_NAMES[name],
            "algorithm": name,
            "dataset": dataset,
            "schema": meta["schema"],
            "features": features,
            "synthetic": meta["synthetic"],
            "live_compatible": meta["live_compatible"],
            "observation": meta["observation"],
            "prefix": meta.get("prefix"),
            "classes": encoder.classes_.tolist(),
            "training_rows": int(train_mask.sum()),
            "seed": seed,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_seconds": training_seconds,
            "dataset_sha256": meta["sha256"],
            "threshold": threshold,
            "calibrated": False,
            "metrics": output,
            "warnings": meta["warnings"] + [str(w.message) for w in caught],
            "background": numeric.loc[train_mask].median().fillna(0).to_dict(),
        }
        bundle = {"pipeline": pipeline, "encoder": encoder, "metadata": metadata}
        temporary = MODELS / f"{model_id}.joblib.tmp"
        joblib.dump(bundle, temporary, compress=3)
        temporary.replace(MODELS / f"{model_id}.joblib")
        temporary_json = MODELS / f"{model_id}.json.tmp"
        temporary_json.write_text(json.dumps(metadata, indent=2))
        temporary_json.replace(MODELS / f"{model_id}.json")
        saved.append(metadata)
        progress(f"Saved {model_id}; held-out macro-F1 {output['test']['macro_f1']:.3f}")
    return saved


def load_model(model_id):
    if not model_id or Path(model_id).name != model_id or not (MODELS / f"{model_id}.json").exists():
        raise ValueError("Unknown model")
    # Only locally trained artifacts; the API never accepts serialized model uploads.
    return joblib.load(MODELS / f"{model_id}.joblib")


def predict(bundle, records, explain=False):
    metadata = bundle["metadata"]
    features = metadata["features"]
    if any(set(features) - set(record) for record in records):
        raise ValueError("Feature schema mismatch; use a model trained with this extractor")
    x = pd.DataFrame(records)[features].replace([np.inf, -np.inf], np.nan)
    start = time.perf_counter()
    pipeline = bundle["pipeline"]
    probabilities = pipeline.predict_proba(x)
    elapsed = 1000 * (time.perf_counter() - start) / len(records)
    classes = metadata["classes"]
    output = []
    for i, probability in enumerate(probabilities):
        cls = int(probability.argmax())
        attack_score = 1 - float(probability[classes.index("BENIGN")]) if "BENIGN" in classes else 1.0
        output.append(
            {
                "prediction": classes[cls],
                "confidence": float(probability[cls]),
                "attack_score": attack_score,
                "inference_ms": elapsed,
                "probabilities": dict(zip(classes, map(float, probability))),
                "threshold": metadata["threshold"],
                "calibrated": False,
            }
        )
    if explain:
        for i in range(min(len(records), 20)):
            explain_start = time.perf_counter()
            output[i]["explanation"] = explain_one(bundle, x.iloc[[i]], output[i]["prediction"])
            output[i]["explanation"]["elapsed_ms"] = (time.perf_counter() - explain_start) * 1000
    return output


def explain_one(bundle, x, predicted):
    meta = bundle["metadata"]
    pipeline = bundle["pipeline"]
    cls = meta["classes"].index(predicted)
    # Probability deltas are directly measured, not claimed to be additive SHAP.
    baseline = float(pipeline.predict_proba(x)[0, cls])
    variants = pd.concat([x] * len(meta["features"]), ignore_index=True)
    for i, feature in enumerate(meta["features"]):
        variants.loc[i, feature] = meta["background"][feature]
    changed = pipeline.predict_proba(variants)[:, cls]
    values = baseline - changed
    method, unit = "Median replacement sensitivity", "probability change"
    try:
        if meta["algorithm"] in {"rf", "extra", "xgboost"}:
            import shap

            transformed = pipeline[:-1].transform(x)
            explainer = shap.TreeExplainer(pipeline[-1])
            attribution = explainer.shap_values(transformed)
            arr = np.asarray(attribution)
            values = arr[0, :, cls] if arr.ndim == 3 else arr[0]
            if arr.ndim == 2 and len(meta["classes"]) == 2 and cls == 0:
                values = -values
            method, unit = "TreeSHAP", "model output contribution"
    except Exception:
        pass  # Exact measured sensitivity remains available for unsupported SHAP versions.
    ranking = np.argsort(-np.abs(values))[:7]
    return {
        "method": method,
        "unit": unit,
        "note": "Explains model behavior, not attack causation. Correlated features can share evidence.",
        "features": [
            {
                "feature": meta["features"][j],
                "value": float(x.iloc[0, j]),
                "contribution": float(values[j]),
                "reference": float(meta["background"][meta["features"][j]]),
            }
            for j in ranking
        ],
    }
