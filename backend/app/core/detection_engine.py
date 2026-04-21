"""
SentinelX Detection Engine
---------------------------
Implements the dual-path detection pipeline:
  Path A: YARA static signature matching
  Path B: GBM feature-based scoring + LLM semantic reasoning (Gemini)
  Fusion: 60% GBM structural score + 40% LLM behavioral signal
"""
import numpy as np
import uuid
import time
import re
import os
import httpx
import json
import logging
from typing import Optional

from app.core.config import settings
from app.core.model_loader import load_models
from app.schemas import (
    ThreatAnalysisResponse, ThreatLevel, DetectionPath,
    YARAResult, LLMAnalysis
)

logger = logging.getLogger(__name__)

# ── Load MITRE Mappings Safely ──────────────────────────────────────────────
def _load_mitre_mappings():
    try:
        mapping_path = os.path.join(os.path.dirname(__file__), "..", "..", "rules", "mitre_mappings.json")
        with open(mapping_path, "r", encoding='utf-8') as f:
            data = json.load(f)
            return data.get("techniques", {})
    except Exception as e:
        logger.warning(f"Failed to load MITRE mappings. Mitre enrichment will be skipped: {e}")
        return {}

MITRE_MAPPINGS = _load_mitre_mappings()


# ── Feature descriptions (for LLM prompt construction) ────────────────────
FEATURE_DESCRIPTIONS = {
    "file_entropy":           "Shannon entropy (high = packed/encrypted)",
    "suspicious_import_count":"Count of suspicious Windows API imports",
    "suspicious_string_count":"Embedded suspicious strings (C2, ransom notes)",
    "anti_debug_calls":       "Anti-debugging API call count",
    "network_indicators":     "Network-related string indicators (IPs, domains)",
    "registry_indicators":    "Registry persistence indicators",
    "has_packing_artifacts":  "UPX/custom packer artifacts detected",
    "pe_timestamp_anomaly":   "PE timestamp is spoofed or anomalous",
    "overlay_ratio":          "Ratio of data appended after PE sections",
    "high_entropy_sections":  "Number of sections with entropy > 6.5",
}

SUSPICIOUS_IMPORTS_MAP = {
    "VirtualAlloc": "Memory allocation for shellcode injection",
    "CreateRemoteThread": "Remote thread injection into other processes",
    "WriteProcessMemory": "Write into another process's memory space",
    "OpenProcess": "Open handle to another process",
    "IsDebuggerPresent": "Anti-debug: check if debugger is attached",
    "URLDownloadToFile": "Download payload from remote URL",
    "RegSetValueEx": "Persistence via registry modification",
    "ShellExecute": "Execute arbitrary commands or files",
}

# ── YARA simulation (for environments without yara-python) ─────────────────
YARA_RULES = {
    "WannaCry_ransomware": {
        "strings": ["WannaCry", "wncry", ".WNCRY", "WannaDecryptor"],
        "description": "WannaCry ransomware variant",
        "mitre": ["T1486", "T1490", "T1210"]
    },
    "Emotet_dropper": {
        "strings": ["Emotet", "loader.dll", "epoch"],
        "description": "Emotet dropper/loader",
        "mitre": ["T1027"]
    },
    "Generic_packer_UPX": {
        "strings": ["UPX!", "UPX0", "UPX1"],
        "description": "UPX-packed executable",
        "mitre": ["T1027.002", "T1027"]
    },
    "Suspicious_network_beacon": {
        "strings": ["InternetOpenUrl", "HttpSendRequest", "URLDownloadToFile"],
        "description": "Network beacon / downloader activity",
        "mitre": ["T1105", "T1071.001"]
    },
    "AntiDebug_evasion": {
        "strings": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
        "description": "Anti-debugging evasion techniques",
        "mitre": ["T1622"]
    },
}

def _simulate_yara_scan(features: dict, strings_sample: list = None) -> tuple[bool, list, float]:
    """
    Simulate YARA scanning based on feature indicators.
    Returns (matched, matched_rules, confidence)
    """
    matched_rules = []
    
    # Check UPX packing
    if features.get("has_upx_signature", 0) == 1:
        matched_rules.append("Generic_packer_UPX")
    
    # Check anti-debug 
    if features.get("anti_debug_calls", 0) >= 2:
        matched_rules.append("AntiDebug_evasion")
    
    # Check network indicators
    if features.get("network_indicators", 0) >= 3:
        matched_rules.append("Suspicious_network_beacon")
    
    # High entropy + packing + no debug = likely packed malware
    entropy = features.get("file_entropy", 0)
    packed  = features.get("has_packing_artifacts", 0)
    if entropy >= 7.2 and packed and features.get("suspicious_import_count", 0) >= 5:
        matched_rules.append("WannaCry_ransomware")

    matched = len(matched_rules) > 0
    confidence = settings.yara_confidence if matched else 0.0
    return matched, matched_rules, confidence


def _build_behavioral_flags(features: dict) -> list:
    flags = []
    if features.get("file_entropy", 0) >= 7.0:
        flags.append(f"High file entropy ({features['file_entropy']:.2f}) — likely packed/encrypted")
    if features.get("anti_debug_calls", 0) > 0:
        flags.append(f"Anti-debug calls detected ({features['anti_debug_calls']})")
    if features.get("network_indicators", 0) > 0:
        flags.append(f"Network C2 indicators ({features['network_indicators']})")
    if features.get("registry_indicators", 0) > 0:
        flags.append(f"Registry persistence indicators ({features['registry_indicators']})")
    if features.get("pe_timestamp_anomaly", 0):
        flags.append("PE timestamp anomaly — likely spoofed")
    if features.get("overlay_ratio", 0) > 0.2:
        flags.append(f"Large PE overlay ({features['overlay_ratio']:.2%}) — appended payload possible")
    if features.get("suspicious_string_count", 0) >= 5:
        flags.append(f"High suspicious string count ({features['suspicious_string_count']})")
    return flags


async def _llm_analyze(features: dict, behavioral_flags: list) -> LLMAnalysis:
    """
    Call Gemini Flash for semantic string/behavioral analysis.
    Falls back to rule-based heuristic if API key not configured.
    """
    api_key = settings.gemini_api_key or os.environ.get("GEMINI_API_KEY", "")

    suspicious_strings = [
        k for k, _ in SUSPICIOUS_IMPORTS_MAP.items()
        if features.get("suspicious_import_count", 0) > 0
    ][:5]

    if not api_key:
        # Rule-based fallback (no API key needed)
        score = (
            0.30 * min(features.get("suspicious_import_count", 0) / 14.0, 1.0) +
            0.25 * min(features.get("suspicious_string_count", 0) / 30.0, 1.0) +
            0.20 * min(features.get("anti_debug_calls", 0) / 8.0, 1.0) +
            0.15 * min(features.get("network_indicators", 0) / 12.0, 1.0) +
            0.10 * features.get("has_packing_artifacts", 0)
        )
        verdict = "MALICIOUS" if score >= 0.4 else ("SUSPICIOUS" if score >= 0.2 else "SAFE")
        reasoning = (
            f"Heuristic analysis: behavioral score {score:.3f}. "
            f"Detected {len(behavioral_flags)} behavioral flags. "
            + (f"Key indicators: {'; '.join(behavioral_flags[:2])}" if behavioral_flags else "No strong indicators.")
        )
        return LLMAnalysis(
            verdict=verdict,
            reasoning=reasoning,
            suspicious_strings=suspicious_strings,
            behavioral_flags=behavioral_flags,
            mitre_techniques=[]
        )

    # Gemini API call
    prompt = f"""You are a malware analyst. Analyze this PE binary feature vector and determine if it is malicious.

Feature Vector:
{json.dumps({k: features.get(k) for k in [
    'file_entropy','suspicious_import_count','suspicious_string_count',
    'anti_debug_calls','network_indicators','registry_indicators',
    'has_packing_artifacts','pe_timestamp_anomaly','overlay_ratio','high_entropy_sections'
]}, indent=2)}

Behavioral flags detected: {behavioral_flags}

Respond ONLY as JSON:
{{
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "SAFE",
  "reasoning": "2-3 sentence explanation of key indicators",
  "suspicious_strings": ["list", "of", "flagged", "imports"],
  "behavioral_flags": ["summarized", "flags"],
  "mitre_techniques": ["T1027", "T1486"]
}}"""

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent",
                params={"key": api_key},
                json={"contents": [{"parts": [{"text": prompt}]}]}
            )
            resp.raise_for_status()
            raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            raw = raw.replace("```json","").replace("```","").strip()
            data = json.loads(raw)
            return LLMAnalysis(**data)
    except Exception as e:
        print("GEMINI API EXCEPTION:", e)
        logger.warning(f"Gemini API fallback: {e}")
        settings.gemini_api_key = ""
        os.environ.pop("GEMINI_API_KEY", None)
        return await _llm_analyze(features, behavioral_flags)  # fallback


async def analyze_features(features: dict, filename: str = None) -> ThreatAnalysisResponse:
    """
    Main analysis pipeline:
      1. YARA static scan (Path A)
      2. GBM scoring + LLM behavioral analysis (Path B)
      3. Hybrid fusion
    """
    t0 = time.time()
    models = load_models()
    scan_id = str(uuid.uuid4())[:8].upper()

    # ── Path A: YARA ─────────────────────────────────────────────────────
    yara_matched, yara_rules, yara_conf = _simulate_yara_scan(features)
    yara_result = YARAResult(
        matched=yara_matched,
        matched_rules=yara_rules,
        confidence=yara_conf
    )

    # ── Path B: GBM scoring ───────────────────────────────────────────────
    feature_names = models["features"]
    fv = np.array([[features.get(f, 0) for f in feature_names]])
    gbm_prob = float(models["gbm"].predict_proba(fv)[0][1])

    # ── LLM behavioral analysis ───────────────────────────────────────────
    behavioral_flags = _build_behavioral_flags(features)
    llm_analysis = await _llm_analyze(features, behavioral_flags)

    # ── Hybrid fusion ─────────────────────────────────────────────────────
    if yara_matched:
        final_score  = settings.yara_confidence
        det_path     = DetectionPath.YARA_STATIC
    else:
        # LLM score from verdict
        llm_score = {"MALICIOUS": 0.9, "SUSPICIOUS": 0.55, "SAFE": 0.1}[llm_analysis.verdict]
        # 60% GBM structural + 40% LLM behavioral
        final_score = np.clip(0.60 * gbm_prob + 0.40 * llm_score, 0, 1)
        det_path = DetectionPath.LLM_HEURISTIC

    # ── Threat classification ─────────────────────────────────────────────
    if final_score >= settings.high_confidence:
        threat_level = ThreatLevel.MALICIOUS
    elif final_score >= settings.malicious_threshold:
        threat_level = ThreatLevel.SUSPICIOUS
    else:
        threat_level = ThreatLevel.SAFE

    # ── Auto-generate YARA rule if malicious ─────────────────────────────
    generated_rule = None
    if threat_level == ThreatLevel.MALICIOUS:
        generated_rule = _generate_yara_rule(scan_id, features, yara_rules, behavioral_flags)

    recommendation = {
        ThreatLevel.MALICIOUS:  "🔴 BLOCK immediately. Quarantine file and isolate endpoint.",
        ThreatLevel.SUSPICIOUS: "🟡 QUARANTINE for further analysis. Do not execute.",
        ThreatLevel.SAFE:       "🟢 File appears benign. Continue with standard monitoring.",
    }[threat_level]

    # ── Aggregate MITRE Techniques ────────────────────────────────────────
    aggregated_mitre = list(llm_analysis.mitre_techniques)
    for rule in yara_rules:
        if rule in YARA_RULES and "mitre" in YARA_RULES[rule]:
            aggregated_mitre.extend(YARA_RULES[rule]["mitre"])
    
    # Remove duplicates but keep elements that exist in mapping or are formally valid
    final_mitre = list(set(aggregated_mitre))

    return ThreatAnalysisResponse(
        scan_id=scan_id,
        filename=filename,
        threat_level=threat_level,
        confidence_score=round(final_score, 4),
        detection_path=det_path,
        yara_result=yara_result,
        llm_analysis=llm_analysis,
        generated_yara_rule=generated_rule,
        processing_time_ms=round((time.time() - t0) * 1000, 2),
        features_extracted=features,
        recommendation=recommendation,
        mitre_techniques=final_mitre
    )


def _generate_yara_rule(scan_id: str, features: dict, yara_rules: list, flags: list) -> str:
    """Auto-generate a YARA rule from detected indicators."""
    strings_block = []
    condition_parts = []

    entropy = features.get("file_entropy", 0)
    if entropy >= 7.0:
        strings_block.append(f'    $entropy_note = "SentinelX: high entropy {entropy:.2f}"')
        condition_parts.append("math.entropy(0, filesize) >= 7.0")

    if features.get("anti_debug_calls", 0) > 0:
        strings_block.append('    $anti_debug1 = "IsDebuggerPresent" ascii')
        strings_block.append('    $anti_debug2 = "CheckRemoteDebuggerPresent" ascii')
        condition_parts.append("any of ($anti_debug*)")

    if features.get("network_indicators", 0) > 0:
        strings_block.append('    $net1 = "URLDownloadToFile" ascii')
        strings_block.append('    $net2 = "InternetOpenUrl" ascii')
        condition_parts.append("any of ($net*)")

    if not strings_block:
        strings_block.append('    $generic = "MZ" at 0')
        condition_parts.append("$generic")

    family_hint = yara_rules[0].split("_")[0] if yara_rules else "Unknown"
    condition = " and\n        ".join(condition_parts) if condition_parts else "any of them"

    return f"""rule SentinelX_AutoGen_{scan_id} {{
    meta:
        description = "Auto-generated by SentinelX v2.0 — {family_hint} family indicators"
        scan_id     = "{scan_id}"
        confidence  = "{features.get('file_entropy',0):.2f}_entropy"
        author      = "SentinelX AI Engine"
        date        = "{time.strftime('%Y-%m-%d')}"
    strings:
{chr(10).join(strings_block)}
    condition:
        uint16(0) == 0x5A4D and  // PE magic bytes
        filesize < 50MB and
        (
            {condition}
        )
}}"""
