"""
CTI-Lab ML Engine — Anomaly Detection for Log Ingestion

Uses Isolation Forest (scikit-learn) to score log batches for anomalous
network activity. The model trains incrementally — each ingested batch
becomes a training sample. Once >= MIN_SAMPLES batches are collected
the model becomes predictive and every new batch gets a real anomaly score.

Persists the model to disk so training survives server restarts.
"""
from __future__ import annotations

import json
import logging
import os
import pickle
from pathlib import Path
from typing import Any

_logger = logging.getLogger("cti.ml")

_MODEL_PATH = Path(os.getenv("CTI_ML_MODEL_PATH", "data/anomaly_model.pkl"))
_MIN_SAMPLES = 15

_FORMAT_CODES: dict[str, float] = {
    "json": 0, "jsonl": 1, "csv": 2, "syslog": 3, "cef": 4,
    "leef": 5, "zeek": 6, "w3c": 7, "kvpairs": 8, "text": 9,
}

_BLOCK_KEYWORDS = ("BLOCK", "DENY", "DROP", "REJECT", "REFUSED")


def _extract_features(
    n_rows: int,
    n_iocs: int,
    n_feed_matches: int,
    events_per_minute: float | None,
    log_format: str,
    volumetry: dict,
) -> list[float]:
    ioc_density = n_iocs / max(n_rows, 1)
    feed_match_ratio = n_feed_matches / max(n_iocs, 1) if n_iocs > 0 else 0.0
    epm = float(events_per_minute or 0)
    fmt_code = _FORMAT_CODES.get(log_format, 9.0)

    by_action: dict = volumetry.get("by_action", {})
    total_actions = max(sum(by_action.values()), 1)
    block_count = sum(
        v for k, v in by_action.items()
        if any(bk in k.upper() for bk in _BLOCK_KEYWORDS)
    )
    block_ratio = block_count / total_actions
    n_unique_actions = float(len(by_action))

    peak_count = float(volumetry.get("peak_count", 0))
    peak_ratio = peak_count / max(n_rows, 1)

    return [
        float(n_rows),
        float(n_iocs),
        ioc_density,
        feed_match_ratio,
        epm,
        fmt_code,
        block_ratio,
        peak_ratio,
        n_unique_actions,
        float(n_feed_matches),
    ]


FEATURE_NAMES = [
    "n_rows", "n_iocs", "ioc_density", "feed_match_ratio",
    "events_per_minute", "format_code", "block_ratio",
    "peak_ratio", "n_unique_actions", "n_feed_matches",
]


class _AnomalyModel:
    def __init__(self) -> None:
        self._samples: list[list[float]] = []
        self._model: Any = None
        self._n_trained: int = 0

    def add_sample(self, features: list[float]) -> None:
        self._samples.append(features)

    def train(self) -> bool:
        if len(self._samples) < _MIN_SAMPLES:
            return False
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest

            X = np.array(self._samples)
            clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            clf.fit(X)
            self._model = clf
            self._n_trained = len(self._samples)
            _logger.info("Anomaly model trained on %d samples", self._n_trained)
            return True
        except ImportError:
            _logger.warning("scikit-learn not available — anomaly scoring disabled")
            return False
        except Exception as exc:
            _logger.error("Model training failed: %s", exc)
            return False

    def score(self, features: list[float]) -> dict:
        warming_up_info = {
            "anomaly_score": 0.0,
            "is_anomaly": False,
            "confidence": 0.0,
            "status": "warming_up",
            "samples_collected": len(self._samples),
            "samples_needed": max(0, _MIN_SAMPLES - len(self._samples)),
        }
        if self._model is None:
            return warming_up_info
        try:
            import numpy as np

            X = np.array([features])
            raw = float(self._model.score_samples(X)[0])
            # score_samples: ~-0.7 = anomaly, ~-0.1 = normal
            # Normalize to [0, 1] where 1 = most anomalous
            normalized = max(0.0, min(1.0, (-raw - 0.1) / 0.6))
            is_anomaly = bool(self._model.predict(X)[0] == -1)
            return {
                "anomaly_score": round(normalized, 3),
                "is_anomaly": is_anomaly,
                "confidence": round(abs(raw), 3),
                "raw_score": round(raw, 4),
                "status": "active",
                "samples_collected": len(self._samples),
            }
        except Exception as exc:
            _logger.error("Scoring error: %s", exc)
            return {"anomaly_score": 0.0, "is_anomaly": False, "status": "error"}

    def save(self, path: Path = _MODEL_PATH) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                pickle.dump({
                    "samples": self._samples,
                    "model": self._model,
                    "n_trained": self._n_trained,
                }, f)
        except Exception as exc:
            _logger.warning("Could not save ML model: %s", exc)

    @classmethod
    def load(cls, path: Path = _MODEL_PATH) -> "_AnomalyModel":
        obj = cls()
        if path.exists():
            try:
                with open(path, "rb") as f:
                    state = pickle.load(f)
                obj._samples = state.get("samples", [])
                obj._model = state.get("model")
                obj._n_trained = state.get("n_trained", 0)
                _logger.info(
                    "ML model loaded — %d samples, trained=%s",
                    len(obj._samples), obj._model is not None,
                )
            except Exception as exc:
                _logger.warning("Could not load ML model (%s) — starting fresh", exc)
        return obj


_model_instance: _AnomalyModel | None = None


def _get_model() -> _AnomalyModel:
    global _model_instance
    if _model_instance is None:
        _model_instance = _AnomalyModel.load()
    return _model_instance


def _build_reason(n_iocs: int, n_feed_matches: int, epm: float | None, volumetry: dict, is_anomaly: bool) -> str:
    reasons: list[str] = []

    if n_feed_matches > 0:
        reasons.append(f"{n_feed_matches} IOC(s) coinciden con actores de amenaza conocidos")

    n_rows = max(volumetry.get("total_events", 1), 1)
    ioc_density = n_iocs / n_rows
    if ioc_density > 0.3:
        reasons.append(f"Alta densidad de IOCs ({ioc_density:.0%} de filas contienen IOCs)")

    if epm and epm > 500:
        reasons.append(f"Volumen elevado de tráfico ({epm:.0f} eventos/min)")

    by_action: dict = volumetry.get("by_action", {})
    total = max(sum(by_action.values()), 1)
    blocks = sum(v for k, v in by_action.items() if any(bk in k.upper() for bk in _BLOCK_KEYWORDS))
    if blocks / total > 0.5:
        reasons.append(f"Alta tasa de bloqueos/rechazos ({blocks/total:.0%})")

    if not reasons:
        if is_anomaly:
            return "Patrón estadístico inusual detectado por el modelo"
        return "Sin indicadores anómalos detectados"
    return "; ".join(reasons)


# ── Public API ─────────────────────────────────────────────────────────────────

def score_log_batch(
    n_rows: int,
    n_iocs: int,
    n_feed_matches: int,
    events_per_minute: float | None,
    log_format: str,
    volumetry: dict,
) -> dict:
    """
    Score a log batch for anomalous activity.
    Also adds this batch to the training buffer and retrains if needed.
    """
    model = _get_model()
    features = _extract_features(n_rows, n_iocs, n_feed_matches, events_per_minute, log_format, volumetry)

    model.add_sample(features)

    n = len(model._samples)
    should_train = (n >= _MIN_SAMPLES and model._model is None) or (n > _MIN_SAMPLES and n % 10 == 0)
    if should_train:
        trained = model.train()
        if trained:
            model.save()

    result = model.score(features)
    result["reason"] = _build_reason(n_iocs, n_feed_matches, events_per_minute, volumetry, result.get("is_anomaly", False))
    result["features"] = dict(zip(FEATURE_NAMES, features))
    return result


def get_model_status() -> dict:
    model = _get_model()
    return {
        "status": "active" if model._model is not None else "warming_up",
        "trained": model._model is not None,
        "samples_collected": len(model._samples),
        "samples_needed": max(0, _MIN_SAMPLES - len(model._samples)),
        "min_samples": _MIN_SAMPLES,
        "n_trained_on": model._n_trained,
    }


def retrain_model() -> dict:
    model = _get_model()
    if len(model._samples) < _MIN_SAMPLES:
        return {
            "success": False,
            "reason": f"Muestras insuficientes ({len(model._samples)}/{_MIN_SAMPLES})",
        }
    trained = model.train()
    if trained:
        model.save()
    return {
        "success": trained,
        "samples": len(model._samples),
        "n_trained_on": model._n_trained,
    }


def reset_model() -> dict:
    global _model_instance
    _model_instance = _AnomalyModel()
    if _MODEL_PATH.exists():
        _MODEL_PATH.unlink(missing_ok=True)
    return {"reset": True}


# ── Supervised RF model (fusion events → FP classifier) ───────────────────────

_SUP_MODEL_PATH = Path(os.getenv("CTI_SUP_MODEL_PATH", "data/supervised_model.pkl"))
_MIN_SUPERVISED_SAMPLES = 50

_SEVERITY_MAP = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_TACTIC_MAP = {
    "reconnaissance": 0, "resource development": 1, "initial access": 2,
    "execution": 3, "persistence": 4, "privilege escalation": 5,
    "defense evasion": 6, "credential access": 7, "discovery": 8,
    "lateral movement": 9, "collection": 10, "command and control": 11,
    "exfiltration": 12, "impact": 13,
}
_THREAT_TYPE_MAP = {
    "malware": 0, "phishing": 1, "ddos": 2, "ransomware": 3,
    "insider threat": 4, "sql injection": 5, "zero-day exploit": 6,
    "data exfiltration": 7,
}

SUPERVISED_FEATURE_NAMES = [
    "confidence_score", "payload_size", "session_duration",
    "source_port", "target_port", "severity_code",
    "tactic_code", "threat_type_code",
    "source_port_privileged", "target_port_privileged",
    "has_ioc", "has_malware",
]


def _extract_event_features(event: dict) -> list[float] | None:
    """Extract numeric features from a single fusion threat event."""
    try:
        confidence = float(event.get("confidenceScore") or 0)
        payload = float(event.get("payloadSize") or 0)
        session = float(event.get("sessionDuration") or 0)
        src_port = float(event.get("sourcePort") or 0)
        tgt_port = float(event.get("targetPort") or 0)

        sev = str(event.get("severity") or "").lower()
        sev_code = float(_SEVERITY_MAP.get(sev, 1))

        tactic = str(event.get("mitreTactic") or "").lower()
        tactic_code = float(_TACTIC_MAP.get(tactic, -1) + 1)

        ttype = str(event.get("threatType") or "").lower()
        type_code = float(_THREAT_TYPE_MAP.get(ttype, -1) + 1)

        src_priv = 1.0 if 0 < src_port < 1024 else 0.0
        tgt_priv = 1.0 if 0 < tgt_port < 1024 else 0.0
        has_ioc = 1.0 if event.get("ioc", "").strip() not in ("", "N/A", "—") else 0.0
        has_malware = 1.0 if event.get("malware", "").strip() not in ("", "N/A", "—", "None") else 0.0

        return [
            confidence, payload, session, src_port, tgt_port,
            sev_code, tactic_code, type_code,
            src_priv, tgt_priv, has_ioc, has_malware,
        ]
    except Exception:
        return None


def _get_label(event: dict) -> int | None:
    v = event.get("isFalsePositive")
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, str):
        return 1 if v.lower() == "true" else 0
    return None


class _SupervisedModel:
    def __init__(self) -> None:
        self._model: Any = None
        self._n_trained: int = 0
        self._n_positive: int = 0
        self._n_negative: int = 0

    def train_from_corpus(self, events: list[dict]) -> bool:
        labeled = [(f, _get_label(e)) for e in events if (f := _extract_event_features(e)) is not None]
        labeled = [(f, lbl) for f, lbl in labeled if lbl is not None]
        if len(labeled) < _MIN_SUPERVISED_SAMPLES:
            return False
        try:
            import numpy as np
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler
            from sklearn.pipeline import Pipeline

            X = np.array([f for f, _ in labeled])
            y = np.array([lbl for _, lbl in labeled])
            self._n_positive = int(y.sum())
            self._n_negative = int(len(y) - y.sum())

            clf = Pipeline([
                ("scaler", StandardScaler()),
                ("rf", RandomForestClassifier(
                    n_estimators=200,
                    max_depth=8,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                )),
            ])
            clf.fit(X, y)
            self._model = clf
            self._n_trained = len(labeled)
            _logger.info(
                "RF supervisado entrenado: %d muestras (%d FP / %d real)",
                self._n_trained, self._n_positive, self._n_negative,
            )
            return True
        except ImportError:
            _logger.warning("scikit-learn no disponible — RF supervisado deshabilitado")
            return False
        except Exception as exc:
            _logger.error("Entrenamiento RF supervisado fallido: %s", exc)
            return False

    def predict(self, event: dict) -> dict:
        features = _extract_event_features(event)
        if features is None or self._model is None:
            return {
                "fp_probability": 0.5,
                "is_likely_fp": False,
                "status": "warming_up" if self._model is None else "feature_error",
            }
        try:
            import numpy as np
            X = np.array([features])
            proba = float(self._model.predict_proba(X)[0][1])
            return {
                "fp_probability": round(proba, 3),
                "is_likely_fp": proba > 0.5,
                "status": "active",
                "features": dict(zip(SUPERVISED_FEATURE_NAMES, features)),
            }
        except Exception as exc:
            _logger.error("Predicción RF: %s", exc)
            return {"fp_probability": 0.5, "is_likely_fp": False, "status": "error"}

    def feature_importances(self) -> dict:
        if self._model is None:
            return {}
        try:
            rf = self._model.named_steps["rf"]
            return dict(zip(SUPERVISED_FEATURE_NAMES, [round(float(i), 4) for i in rf.feature_importances_]))
        except Exception:
            return {}

    def save(self, path: Path = _SUP_MODEL_PATH) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                pickle.dump({
                    "model": self._model,
                    "n_trained": self._n_trained,
                    "n_positive": self._n_positive,
                    "n_negative": self._n_negative,
                }, f)
        except Exception as exc:
            _logger.warning("No se pudo guardar RF supervisado: %s", exc)

    @classmethod
    def load(cls, path: Path = _SUP_MODEL_PATH) -> "_SupervisedModel":
        obj = cls()
        if path.exists():
            try:
                with open(path, "rb") as f:
                    state = pickle.load(f)
                obj._model = state.get("model")
                obj._n_trained = state.get("n_trained", 0)
                obj._n_positive = state.get("n_positive", 0)
                obj._n_negative = state.get("n_negative", 0)
                _logger.info(
                    "RF supervisado cargado — %d muestras (FP=%d / Real=%d)",
                    obj._n_trained, obj._n_positive, obj._n_negative,
                )
            except Exception as exc:
                _logger.warning("No se pudo cargar RF supervisado (%s) — iniciando limpio", exc)
        return obj


_sup_model_instance: _SupervisedModel | None = None


def _get_sup_model() -> _SupervisedModel:
    global _sup_model_instance
    if _sup_model_instance is None:
        _sup_model_instance = _SupervisedModel.load()
    return _sup_model_instance


def _load_corpus_events() -> list[dict]:
    """Pull all events from fusion_corpus table."""
    try:
        import os as _os
        import sqlite3 as _sqlite3

        db_path = _os.getenv("DB_PATH", "/data/cti.db")
        conn = _sqlite3.connect(db_path)
        conn.row_factory = _sqlite3.Row
        rows = conn.execute(
            "SELECT events_json FROM fusion_corpus ORDER BY created_at"
        ).fetchall()
        conn.close()

        events: list[dict] = []
        for row in rows:
            try:
                batch = json.loads(row["events_json"] or "[]")
                if isinstance(batch, list):
                    events.extend(batch)
            except Exception:
                pass
        return events
    except Exception as exc:
        _logger.error("Error cargando corpus desde BD: %s", exc)
        return []


# ── Corpus management public API ───────────────────────────────────────────────

def save_fusion_events_to_corpus(
    events: list[dict],
    query: str,
    created_by: str = "system",
    is_annual: bool = False,
) -> dict:
    """
    Persist a fusion event batch in fusion_corpus and retrain the RF if
    enough samples are now available.
    """
    if not events:
        return {"saved": 0, "retrained": False}

    actor = events[0].get("threatActor", "") if events else ""
    try:
        import os as _os
        import sqlite3 as _sqlite3

        db_path = _os.getenv("DB_PATH", "/data/cti.db")
        conn = _sqlite3.connect(db_path)
        conn.execute(
            """
            INSERT INTO fusion_corpus (query, actor, events_json, event_count, is_annual, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                query[:500],
                actor[:200],
                json.dumps(events, ensure_ascii=False),
                len(events),
                int(is_annual),
                created_by[:200],
            ),
        )
        conn.commit()
        conn.close()
        _logger.info("Corpus: +%d eventos guardados (query='%s')", len(events), query[:60])
    except Exception as exc:
        _logger.error("Error guardando corpus: %s", exc)
        return {"saved": 0, "retrained": False}

    # Attempt retraining with full corpus
    all_events = _load_corpus_events()
    labeled_count = sum(1 for e in all_events if _get_label(e) is not None)
    retrained = False
    if labeled_count >= _MIN_SUPERVISED_SAMPLES:
        sup = _get_sup_model()
        retrained = sup.train_from_corpus(all_events)
        if retrained:
            sup.save()

    return {
        "saved": len(events),
        "corpus_total": len(all_events),
        "labeled_events": labeled_count,
        "retrained": retrained,
    }


def get_supervised_model_status() -> dict:
    sup = _get_sup_model()
    all_events = _load_corpus_events()
    labeled = sum(1 for e in all_events if _get_label(e) is not None)
    return {
        "status": "active" if sup._model is not None else "warming_up",
        "trained": sup._model is not None,
        "n_trained_on": sup._n_trained,
        "n_positive_fp": sup._n_positive,
        "n_negative_real": sup._n_negative,
        "corpus_events": len(all_events),
        "labeled_events": labeled,
        "min_samples_needed": _MIN_SUPERVISED_SAMPLES,
        "samples_needed": max(0, _MIN_SUPERVISED_SAMPLES - labeled),
        "feature_importances": sup.feature_importances(),
    }


def retrain_supervised_model() -> dict:
    all_events = _load_corpus_events()
    labeled = sum(1 for e in all_events if _get_label(e) is not None)
    if labeled < _MIN_SUPERVISED_SAMPLES:
        return {
            "success": False,
            "reason": f"Eventos etiquetados insuficientes ({labeled}/{_MIN_SUPERVISED_SAMPLES})",
            "corpus_events": len(all_events),
        }
    global _sup_model_instance
    _sup_model_instance = _SupervisedModel()
    sup = _get_sup_model()
    trained = sup.train_from_corpus(all_events)
    if trained:
        sup.save()
    return {
        "success": trained,
        "corpus_events": len(all_events),
        "labeled_events": labeled,
        "n_trained_on": sup._n_trained,
        "feature_importances": sup.feature_importances(),
    }


def predict_false_positive(event: dict) -> dict:
    """Predict false-positive probability for a single fusion event."""
    sup = _get_sup_model()
    return sup.predict(event)


def batch_predict_false_positives(events: list[dict]) -> list[dict]:
    """Predict FP probability for each event in a list."""
    sup = _get_sup_model()
    return [sup.predict(e) for e in events]
