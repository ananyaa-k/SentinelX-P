from fastapi import APIRouter, HTTPException, Query
from app.schemas import DatasetInfoResponse, SampleRecord
from app.core.model_loader import load_models
from app.core.config import settings
import pandas as pd
import numpy as np
import logging
from pathlib import Path
from typing import List, Optional

router = APIRouter()
logger = logging.getLogger(__name__)

MALWARE_FAMILIES = [
    "Ransomware.WannaCry","Ransomware.LockBit","Trojan.AgentTesla",
    "Trojan.Emotet","Backdoor.CobaltStrike","Infostealer.RedLine",
    "Dropper.GuLoader","Worm.Conficker","RAT.AsyncRAT","Spyware.FormBook"
]
BENIGN_CATEGORIES = [
    "Windows.System32","Microsoft.Office","Browser.Chrome","AV.Defender",
    "Dev.VSCode","Runtime.DotNet","Util.Sysinternals","Driver.Signed",
    "Media.VLC","Productivity.7zip"
]


def _load_df():
    path = Path(__file__).parent.parent.parent / "data" / "sentinelx_dataset.csv"
    if path.exists():
        return pd.read_csv(path)
    raise HTTPException(status_code=503, detail="Dataset not available")


@router.get("/info", response_model=DatasetInfoResponse,
            summary="Dataset statistics and composition")
async def dataset_info():
    """
    Returns full metadata about the SentinelX evaluation dataset.
    
    Dataset characteristics:
    - 250 PE feature samples (150 malware, 100 benign)
    - 10 malware families including ransomware, trojans, RATs, wipers
    - 22 static PE features per sample
    - Features derived from published distributions (Saxe & Berlin 2015, TESSERACT 2019)
    """
    models = load_models()
    bench  = models["benchmark"]
    di     = bench["dataset_info"]
    features = models["features"]

    return DatasetInfoResponse(
        total_samples=di["total_samples"],
        malware_count=di["malware"],
        benign_count=di["benign"],
        malware_families=MALWARE_FAMILIES,
        benign_categories=BENIGN_CATEGORIES,
        packed_malware=di["packed_malware"],
        evasive_malware=di["evasive_malware"],
        train_size=di["train_size"],
        test_size=di["test_size"],
        features=features,
        feature_count=len(features),
        citation=(
            "Feature distributions derived from: Saxe & Berlin (2015) IEEE MALWARE; "
            "Pendlebury et al. (2019) USENIX TESSERACT; Gandotra et al. (2014) J. Information Security."
        )
    )


@router.get("/samples", summary="Browse dataset samples (paginated)")
async def get_samples(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=5, le=100),
    label: Optional[int] = Query(None, ge=0, le=1, description="Filter: 0=benign, 1=malware"),
    family: Optional[str] = Query(None, description="Filter by family name")
):
    """Browse the dataset with pagination and optional filtering."""
    df = _load_df()
    models = load_models()

    if label is not None:
        df = df[df["label"] == label]
    if family:
        df = df[df["family"].str.contains(family, case=False, na=False)]

    total = len(df)
    start = (page - 1) * per_page
    page_df = df.iloc[start:start + per_page]

    # Score each sample with GBM
    FEATURES = models["features"]
    X = page_df[[f for f in FEATURES if f in page_df.columns]].fillna(0).values
    scores = models["gbm"].predict_proba(X)[:, 1].tolist()

    samples = []
    for i, (_, row) in enumerate(page_df.iterrows()):
        samples.append(SampleRecord(
            sha256=row["sha256"],
            label=int(row["label"]),
            label_text="malicious" if row["label"] == 1 else "benign",
            family=row["family"],
            file_entropy=float(row["file_entropy"]),
            is_packed=int(row.get("is_packed", 0)),
            yara_detection=int(row.get("yara_only_detection", 0)),
            threat_score=round(scores[i], 4) if i < len(scores) else None
        ))

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "samples": samples
    }


@router.get("/stats/families", summary="Malware family distribution")
async def family_stats():
    """Returns sample count per malware family and benign category."""
    df = _load_df()
    dist = df.groupby(["family","label"]).size().reset_index(name="count")
    return {
        "families": dist.to_dict(orient="records"),
        "total_families": df["family"].nunique()
    }
