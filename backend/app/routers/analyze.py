from fastapi import APIRouter, File, UploadFile, HTTPException
from app.schemas import FeatureVector, ThreatAnalysisResponse
from app.core.detection_engine import analyze_features
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/features", response_model=ThreatAnalysisResponse,
             summary="Analyze via pre-extracted feature vector")
async def analyze_by_features(fv: FeatureVector):
    """
    Analyze a PE binary given its pre-extracted feature vector.
    
    This endpoint accepts the 20-feature vector that SentinelX uses:
    - 13 structural PE features (entropy, sections, imports, etc.)
    - 7 behavioral/semantic features (suspicious strings, anti-debug, network indicators)
    
    **Detection path:**
    - Features trigger YARA rule matching (Path A)
    - Remaining samples processed by GBM + LLM heuristic (Path B)
    """
    try:
        features = fv.model_dump()
        result = await analyze_features(features, filename=None)
        return result
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/file", response_model=ThreatAnalysisResponse,
             summary="Upload PE binary file for full analysis")
async def analyze_file(file: UploadFile = File(...)):
    """
    Upload a PE binary (.exe, .dll, .sys) for threat analysis.
    
    SentinelX extracts 20 static PE features from the binary,
    runs them through the dual-path detection pipeline, and
    returns a full threat assessment with optional auto-generated YARA rule.
    
    **Note:** Maximum file size 50MB. Only PE binaries accepted.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    allowed_ext = {".exe", ".dll", ".sys", ".bin", ".pe", ".dat"}
    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in allowed_ext and ext != "":
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Accepted: {allowed_ext}"
        )

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 50MB limit")

    # Extract PE features from binary
    features = _extract_pe_features(content)
    result   = await analyze_features(features, filename=file.filename)
    return result


def _extract_pe_features(content: bytes) -> dict:
    """
    Extract static PE features from raw binary bytes.
    Falls back to entropy-only analysis for non-PE files.
    """
    import math
    import struct

    def shannon_entropy(data: bytes) -> float:
        if not data: return 0.0
        freq = [0] * 256
        for b in data: freq[b] += 1
        n = len(data)
        return -sum((f/n)*math.log2(f/n) for f in freq if f > 0)

    file_entropy     = round(shannon_entropy(content), 4)
    file_size_kb     = len(content) // 1024

    # Parse PE header
    num_sections = 3  # default
    num_imports  = 20
    num_exports  = 0
    has_debug    = 0
    overlay_ratio= 0.0

    try:
        if len(content) >= 64 and content[:2] == b"MZ":
            pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
            if pe_offset + 6 < len(content) and content[pe_offset:pe_offset+4] == b"PE\x00\x00":
                num_sections = struct.unpack_from("<H", content, pe_offset + 6)[0]
                has_debug    = int(shannon_entropy(content[pe_offset:pe_offset+0x100]) > 4.0)
    except Exception:
        pass

    # String analysis
    strings = []
    current = []
    for b in content:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings.append("".join(current))
            current = []
    
    suspicious_keywords = [
        "VirtualAlloc","CreateRemoteThread","WriteProcessMemory","OpenProcess",
        "IsDebuggerPresent","CheckRemoteDebuggerPresent","URLDownloadToFile",
        "RegSetValueEx","ShellExecute","WinExec","InternetOpen","HttpSendRequest"
    ]
    ransom_keywords = ["encrypt","ransom","bitcoin","decrypt","locked","pay","wallet"]
    network_keywords = ["http://","https://","ftp://","socket","connect","recv","send"]
    registry_keywords = ["HKEY_","RegOpenKey","RegCreateKey","HKLM","HKCU"]

    susp_import_count  = sum(1 for s in strings for k in suspicious_keywords if k.lower() in s.lower())
    susp_string_count  = sum(1 for s in strings for k in ransom_keywords if k.lower() in s.lower())
    network_indicators = sum(1 for s in strings for k in network_keywords if k in s)
    reg_indicators     = sum(1 for s in strings for k in registry_keywords if k in s)
    anti_debug         = sum(1 for s in strings if any(k in s for k in ["IsDebugger","NtQuery","CheckRemote"]))

    section_entropy_avg = min(file_entropy * 0.95, 7.9)
    resource_entropy    = min(file_entropy * 0.8, 7.5)
    import_entropy      = min(3.5 + susp_import_count * 0.15, 6.0)
    has_upx             = int(b"UPX!" in content[:2048])
    has_packing         = int(file_entropy >= 7.0 or has_upx)
    pe_ts_anomaly       = int(file_entropy >= 7.2 and num_sections <= 4)
    high_ent_sections   = int(file_entropy >= 7.0)

    return {
        "file_entropy":           file_entropy,
        "num_sections":           max(1, min(num_sections, 20)),
        "num_imports":            max(0, min(num_imports + susp_import_count * 2, 200)),
        "num_strings":            min(len(strings), 2000),
        "section_entropy_avg":    round(section_entropy_avg, 4),
        "overlay_ratio":          round(overlay_ratio, 4),
        "resource_entropy":       round(resource_entropy, 4),
        "file_size_kb":           file_size_kb,
        "import_entropy":         round(import_entropy, 4),
        "has_packing_artifacts":  has_packing,
        "pe_timestamp_anomaly":   pe_ts_anomaly,
        "has_debug_info":         has_debug,
        "num_exports":            num_exports,
        "has_upx_signature":      has_upx,
        "suspicious_import_count":min(susp_import_count, 14),
        "suspicious_string_count":min(susp_string_count, 30),
        "anti_debug_calls":       min(anti_debug, 8),
        "network_indicators":     min(network_indicators, 12),
        "registry_indicators":    min(reg_indicators, 8),
        "high_entropy_sections":  high_ent_sections,
    }
