import joblib, json, logging
from functools import lru_cache
from app.core.config import settings
import shutil, pathlib

logger = logging.getLogger(__name__)

_models: dict = {}

def load_models() -> dict:
    global _models
    if _models:
        return _models

    try:
        _models["gbm"]       = joblib.load(settings.gbm_path)
        _models["dt"]        = joblib.load(settings.dt_path)
        _models["features"]  = json.load(open(settings.features_path))
        _models["benchmark"] = json.load(open(settings.benchmark_path))
        _models["fi"]        = json.load(open(settings.fi_path))

        # Copy dataset to data/ if not already there
        if not settings.dataset_path.exists():
            settings.dataset_path.parent.mkdir(parents=True, exist_ok=True)
            src = settings.model_dir.parent / ".." / "sentinelx_dataset.csv"
            if src.exists():
                shutil.copy(src, settings.dataset_path)

        logger.info("✅ SentinelX models loaded: GBM + Decision Tree")
        return _models
    except Exception as e:
        logger.error(f"Model load failed: {e}")
        raise RuntimeError(f"Failed to load models: {e}")
