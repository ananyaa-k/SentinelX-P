from pydantic_settings import BaseSettings
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    app_name: str = "SentinelX"
    version:  str = "2.0.0"
    
    # Model paths
    model_dir:    Path = BASE_DIR / "models"
    gbm_path:     Path = BASE_DIR / "models" / "sentinelx_gbm.pkl"
    dt_path:      Path = BASE_DIR / "models" / "basic_ml_dt.pkl"
    features_path:Path = BASE_DIR / "models" / "features.json"
    benchmark_path:Path= BASE_DIR / "models" / "benchmark_results.json"
    fi_path:      Path = BASE_DIR / "models" / "feature_importances.json"
    
    # Data
    dataset_path: Path = BASE_DIR / "data" / "sentinelx_dataset.csv"
    rules_dir:    Path = BASE_DIR / "rules"
    
    # Analysis thresholds
    malicious_threshold: float = 0.46
    high_confidence:     float = 0.80
    yara_confidence:     float = 0.97
    
    # Gemini (optional — used for LLM string explanation)
    gemini_api_key: str = ""
    gemini_model:   str = "gemini-2.5-flash"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
