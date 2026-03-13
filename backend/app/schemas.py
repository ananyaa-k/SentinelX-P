from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

# ── Enums ─────────────────────────────────────────────────────────────────
class ThreatLevel(str, Enum):
    SAFE       = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS  = "MALICIOUS"

class DetectionPath(str, Enum):
    YARA_STATIC  = "YARA_STATIC"    # Path A: signature match
    LLM_HEURISTIC= "LLM_HEURISTIC"  # Path B: heuristic/GBM analysis
    HYBRID       = "HYBRID"         # Both paths triggered

# ── Feature input schema (for /analyze/features) ─────────────────────────
class FeatureVector(BaseModel):
    file_entropy:          float = Field(..., ge=0.0, le=8.0,   description="Shannon entropy of file (0–8)")
    num_sections:          int   = Field(..., ge=0,   le=30,    description="PE section count")
    num_imports:           int   = Field(..., ge=0,   le=500,   description="Number of imported functions")
    num_strings:           int   = Field(..., ge=0,              description="Printable ASCII string count")
    section_entropy_avg:   float = Field(..., ge=0.0, le=8.0)
    overlay_ratio:         float = Field(..., ge=0.0, le=1.0,   description="Ratio of overlay to file size")
    resource_entropy:      float = Field(..., ge=0.0, le=8.0)
    file_size_kb:          int   = Field(..., ge=0)
    import_entropy:        float = Field(..., ge=0.0, le=8.0)
    has_packing_artifacts: int   = Field(..., ge=0, le=1)
    pe_timestamp_anomaly:  int   = Field(..., ge=0, le=1,       description="1 if timestamp is future/epoch")
    has_debug_info:        int   = Field(..., ge=0, le=1)
    num_exports:           int   = Field(..., ge=0)
    has_upx_signature:     int   = Field(..., ge=0, le=1)
    suspicious_import_count:int  = Field(..., ge=0)
    suspicious_string_count:int  = Field(..., ge=0)
    anti_debug_calls:      int   = Field(..., ge=0)
    network_indicators:    int   = Field(..., ge=0)
    registry_indicators:   int   = Field(..., ge=0)
    high_entropy_sections: int   = Field(..., ge=0)

    class Config:
        json_schema_extra = {
            "example": {
                "file_entropy": 7.2, "num_sections": 3, "num_imports": 14,
                "num_strings": 48, "section_entropy_avg": 6.8, "overlay_ratio": 0.31,
                "resource_entropy": 6.1, "file_size_kb": 184, "import_entropy": 3.2,
                "has_packing_artifacts": 1, "pe_timestamp_anomaly": 1,
                "has_debug_info": 0, "num_exports": 0, "has_upx_signature": 0,
                "suspicious_import_count": 7, "suspicious_string_count": 9,
                "anti_debug_calls": 2, "network_indicators": 4,
                "registry_indicators": 2, "high_entropy_sections": 2
            }
        }

# ── Analysis response ─────────────────────────────────────────────────────
class YARAResult(BaseModel):
    matched:          bool
    matched_rules:    List[str]
    confidence:       float

class LLMAnalysis(BaseModel):
    verdict:          str
    reasoning:        str
    suspicious_strings: List[str]
    behavioral_flags: List[str]

class ThreatAnalysisResponse(BaseModel):
    scan_id:          str
    filename:         Optional[str]
    threat_level:     ThreatLevel
    confidence_score: float = Field(..., description="0.0–1.0 threat confidence")
    detection_path:   DetectionPath
    yara_result:      YARAResult
    llm_analysis:     LLMAnalysis
    generated_yara_rule: Optional[str] = None
    processing_time_ms:  float
    features_extracted:  Dict[str, Any]
    recommendation:   str

# ── Benchmark schemas ─────────────────────────────────────────────────────
class ApproachMetrics(BaseModel):
    accuracy:   float
    precision:  float
    recall:     float
    f1:         float
    fpr:        float
    fnr:        float
    tp: int; tn: int; fp: int; fn: int
    auc:        Optional[float] = None

class BenchmarkResponse(BaseModel):
    yara_only:   ApproachMetrics
    basic_ml:    ApproachMetrics
    sentinelx:   ApproachMetrics
    improvements: Dict[str, float]
    dataset_info: Dict[str, Any]
    note: str

# ── Dataset schemas ───────────────────────────────────────────────────────
class DatasetInfoResponse(BaseModel):
    total_samples:      int
    malware_count:      int
    benign_count:       int
    malware_families:   List[str]
    benign_categories:  List[str]
    packed_malware:     int
    evasive_malware:    int
    train_size:         int
    test_size:          int
    features:           List[str]
    feature_count:      int
    citation:           str

class SampleRecord(BaseModel):
    sha256:        str
    label:         int
    label_text:    str
    family:        str
    file_entropy:  float
    is_packed:     int
    yara_detection:int
    threat_score:  Optional[float] = None

# ── Model schemas ─────────────────────────────────────────────────────────
class FeatureImportance(BaseModel):
    feature:    str
    importance: float
    rank:       int
    description:str

class ModelExplainResponse(BaseModel):
    model_name:          str
    top_features:        List[FeatureImportance]
    architecture_summary:str
    fusion_weights:      Dict[str, float]
    note: str
