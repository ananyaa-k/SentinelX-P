import pytest
from app.schemas import LLMAnalysis, ThreatAnalysisResponse, MITRE_ID_RE
from pydantic import ValidationError

def test_mitre_id_regex_valid():
    """Test that valid MITRE IDs match the regex."""
    valid_ids = ["T1486", "T1056.001", "T1027", "T1071.001"]
    for id_ in valid_ids:
        assert MITRE_ID_RE.match(id_)

def test_mitre_id_regex_invalid():
    """Test adversarial 'Spoof' inputs and shell-injection shaped strings fail."""
    invalid_ids = [
        "T1486;",
        "T1486 && ls",
        "$(whoami)",
        "T1056..001",
        "t1486",       # case sensitive
        "T14860",      # too many digits
        "T1486.12",    # too few decimal digits
        "T1486.1234",  # too many decimal digits
        "T14",         # too short
        "<script>alert(1)</script>",
        "T1027\n"
    ]
    for id_ in invalid_ids:
        assert not MITRE_ID_RE.match(id_), f"Failed on {id_}"

def test_pydantic_mitre_validation():
    """Ensure pydantic models reject invalid MITRE IDs (try/except wrapper check)."""
    with pytest.raises(ValidationError):
        LLMAnalysis(
            verdict="MALICIOUS",
            reasoning="Test",
            suspicious_strings=[],
            behavioral_flags=[],
            mitre_techniques=["T1486", "T1486 && rm -rf /"]
        )

def test_pydantic_valid_mitre():
    """Ensure pydantic models accept valid MITRE IDs."""
    model = LLMAnalysis(
        verdict="MALICIOUS",
        reasoning="Test",
        suspicious_strings=[],
        behavioral_flags=[],
        mitre_techniques=["T1486", "T1027.002"]
    )
    assert len(model.mitre_techniques) == 2

