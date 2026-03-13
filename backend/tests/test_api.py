"""
SentinelX Test Suite
pytest tests/test_api.py -v
"""
import pytest
from fastapi.testclient import TestClient
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.main import app

client = TestClient(app)

# ── Fixtures ──────────────────────────────────────────────────────────────
MALWARE_FEATURES = {
    "file_entropy": 7.45, "num_sections": 3, "num_imports": 11,
    "num_strings": 42, "section_entropy_avg": 7.1, "overlay_ratio": 0.38,
    "resource_entropy": 6.5, "file_size_kb": 168, "import_entropy": 3.1,
    "has_packing_artifacts": 1, "pe_timestamp_anomaly": 1,
    "has_debug_info": 0, "num_exports": 0, "has_upx_signature": 0,
    "suspicious_import_count": 8, "suspicious_string_count": 11,
    "anti_debug_calls": 3, "network_indicators": 5,
    "registry_indicators": 2, "high_entropy_sections": 2
}

BENIGN_FEATURES = {
    "file_entropy": 4.2, "num_sections": 7, "num_imports": 88,
    "num_strings": 412, "section_entropy_avg": 3.8, "overlay_ratio": 0.01,
    "resource_entropy": 2.9, "file_size_kb": 2048, "import_entropy": 5.6,
    "has_packing_artifacts": 0, "pe_timestamp_anomaly": 0,
    "has_debug_info": 1, "num_exports": 12, "has_upx_signature": 0,
    "suspicious_import_count": 0, "suspicious_string_count": 0,
    "anti_debug_calls": 0, "network_indicators": 0,
    "registry_indicators": 0, "high_entropy_sections": 0
}

# ── Health tests ──────────────────────────────────────────────────────────
def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "SentinelX" in r.json()["name"]

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

# ── Analyze tests ─────────────────────────────────────────────────────────
def test_analyze_malware_features():
    r = client.post("/analyze/features", json=MALWARE_FEATURES)
    assert r.status_code == 200
    data = r.json()
    assert data["threat_level"] in ("MALICIOUS", "SUSPICIOUS")
    assert data["confidence_score"] > 0.4
    assert "scan_id" in data
    assert "recommendation" in data

def test_analyze_benign_features():
    r = client.post("/analyze/features", json=BENIGN_FEATURES)
    assert r.status_code == 200
    data = r.json()
    assert data["threat_level"] == "SAFE"
    assert data["confidence_score"] < 0.46

def test_analyze_malware_generates_yara_rule():
    r = client.post("/analyze/features", json=MALWARE_FEATURES)
    assert r.status_code == 200
    data = r.json()
    if data["threat_level"] == "MALICIOUS":
        assert data["generated_yara_rule"] is not None
        assert "rule SentinelX_AutoGen_" in data["generated_yara_rule"]

def test_analyze_validation_error():
    bad = {**MALWARE_FEATURES, "file_entropy": 99.0}  # out of range
    r = client.post("/analyze/features", json=bad)
    assert r.status_code == 422

def test_analyze_file_wrong_type():
    r = client.post("/analyze/file",
                    files={"file": ("test.pdf", b"fake content", "application/pdf")})
    assert r.status_code == 415

def test_analyze_file_pe():
    # Minimal MZ header
    mz = b"MZ" + b"\x00" * 62 + b"\x40\x00\x00\x00" + b"\x00" * 60 + b"PE\x00\x00"
    r = client.post("/analyze/file",
                    files={"file": ("suspicious.exe", mz, "application/octet-stream")})
    assert r.status_code == 200
    assert "threat_level" in r.json()

# ── Benchmark tests ───────────────────────────────────────────────────────
def test_benchmark_results():
    r = client.get("/benchmark/results")
    assert r.status_code == 200
    data = r.json()
    assert "yara_only" in data
    assert "basic_ml" in data
    assert "sentinelx" in data
    sx = data["sentinelx"]
    assert sx["accuracy"] > 90
    assert sx["recall"] > 95

def test_benchmark_sentinelx_beats_yara():
    r = client.get("/benchmark/results")
    data = r.json()
    assert data["sentinelx"]["recall"] > data["yara_only"]["recall"]
    assert data["sentinelx"]["f1"]     > data["yara_only"]["f1"]
    assert data["improvements"]["fnr_reduction_pct"] > 0

def test_benchmark_live_run():
    r = client.post("/benchmark/run?n_samples=20")
    assert r.status_code == 200
    data = r.json()
    assert data["n_samples"] == 20
    assert len(data["samples"]) == 20
    assert data["sentinelx_accuracy"] > 0

def test_benchmark_invalid_samples():
    r = client.post("/benchmark/run?n_samples=500")
    assert r.status_code == 400

# ── Dataset tests ─────────────────────────────────────────────────────────
def test_dataset_info():
    r = client.get("/dataset/info")
    assert r.status_code == 200
    data = r.json()
    assert data["total_samples"] == 250
    assert data["malware_count"] == 150
    assert data["benign_count"] == 100
    assert len(data["malware_families"]) == 10
    assert data["feature_count"] == 20

def test_dataset_samples_pagination():
    r = client.get("/dataset/samples?page=1&per_page=10")
    assert r.status_code == 200
    data = r.json()
    assert len(data["samples"]) == 10
    assert data["total"] == 250

def test_dataset_samples_filter_malware():
    r = client.get("/dataset/samples?label=1&per_page=50")
    assert r.status_code == 200
    data = r.json()
    for s in data["samples"]:
        assert s["label"] == 1

def test_dataset_family_stats():
    r = client.get("/dataset/stats/families")
    assert r.status_code == 200
    data = r.json()
    assert data["total_families"] == 20

# ── Model tests ───────────────────────────────────────────────────────────
def test_model_explain():
    r = client.get("/model/explain")
    assert r.status_code == 200
    data = r.json()
    assert len(data["top_features"]) == 20
    assert data["top_features"][0]["rank"] == 1
    assert data["fusion_weights"]["gbm_structural"] == 0.60
    assert data["fusion_weights"]["llm_behavioral"] == 0.40

def test_model_info():
    r = client.get("/model/info")
    assert r.status_code == 200
    data = r.json()
    assert data["sentinelx_model"]["n_estimators"] == 150
    assert data["sentinelx_model"]["test_recall"] == 100.0
    assert data["fusion_config"]["threshold"] == 0.46
