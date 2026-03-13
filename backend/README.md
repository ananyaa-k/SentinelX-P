# SentinelX v2.0 — Hybrid Malware Detection Framework

> Combining YARA static signatures with Generative AI heuristics for automated zero-day detection and YARA rule synthesis.

**Paper:** *Malware Detection via Signature-Based Pattern Matching: An Optimized Algorithmic Approach to Efficient Scanning*  
**Authors:** K. Sharath Kumar, M. Archana, M. Abhign Reddy, K. Ananya  
**Institution:** CMR College of Engineering & Technology, Telangana, India

---

## Architecture

```
Binary Input
     │
     ▼
┌─────────────────┐        Path A: Known Threat
│  YARA Engine    │──── MATCH ──────────────────► MALICIOUS (confidence: 0.97)
│  (Static Rules) │
└────────┬────────┘
         │ NO MATCH
         ▼
┌─────────────────────────────────────────────┐
│  Path B: Zero-Day / Evasive Threat          │
│                                             │
│  ┌──────────────┐    ┌───────────────────┐  │
│  │ GBM Model    │    │  LLM Semantic     │  │
│  │ (structural) │    │  (Gemini Flash)   │  │
│  │  20 features │    │  string analysis  │  │
│  └──────┬───────┘    └────────┬──────────┘  │
│         │   60% weight        │ 40% weight  │
│         └──────────┬──────────┘             │
│                    ▼                        │
│           Hybrid Score ≥ 0.46?             │
│           YES → MALICIOUS / SUSPICIOUS     │
│           NO  → SAFE                       │
└─────────────────────────────────────────────┘
         │
         ▼ (if MALICIOUS)
Auto-Generated YARA Rule → Threat Intelligence Feed
```

## Benchmark Results

| Approach       | Accuracy | Precision | Recall  | F1      | FPR    | FNR     |
|----------------|----------|-----------|---------|---------|--------|---------|
| YARA-Only      | 73.33%   | 100.00%   | 55.56%  | 71.43%  | 0.00%  | 44.44%  |
| Basic-ML (DT)  | 92.00%   | 91.67%    | 92.86%  | 92.26%  | 7.14%  | 7.14%   |
| **SentinelX**  | **98.67%**| **97.83%**| **100%**| **97.83%**| **2.67%** | **0.0%** |

*Evaluated on n=75 held-out test samples (30/70 stratified split from 250-sample dataset)*  
*5-fold cross-validation F1: 96.71% ± 1.68%*

**SentinelX reduces false negatives (missed malware) by 44.44% over YARA-only.**

## Dataset

- **250 PE feature samples**: 150 malware, 100 benign
- **10 malware families**: Ransomware.WannaCry, Ransomware.LockBit, Trojan.AgentTesla, Trojan.Emotet, Backdoor.CobaltStrike, Infostealer.RedLine, Dropper.GuLoader, Worm.Conficker, RAT.AsyncRAT, Spyware.FormBook
- **20 features per sample**: structural PE + behavioral/semantic indicators
- **Dataset:** `data/sentinelx_dataset.csv`
- **Feature basis:** Saxe & Berlin (2015), Pendlebury et al. (2019), Gandotra et al. (2014)

## API Endpoints

| Method | Endpoint              | Description                                    |
|--------|-----------------------|------------------------------------------------|
| POST   | `/analyze/features`   | Analyze via pre-extracted 20-feature vector    |
| POST   | `/analyze/file`       | Upload PE binary for full analysis             |
| GET    | `/benchmark/results`  | 3-way benchmark comparison table               |
| POST   | `/benchmark/run`      | Live benchmark on n random samples             |
| GET    | `/dataset/info`       | Dataset statistics and composition             |
| GET    | `/dataset/samples`    | Paginated sample browser with filtering        |
| GET    | `/model/explain`      | GBM feature importance rankings                |
| GET    | `/model/info`         | Full model architecture and hyperparameters    |

Interactive docs available at: `http://localhost:8000/docs`

## Setup

```bash
# Clone
git clone https://github.com/ananyaa-k/SentinelX
cd SentinelX

# Install
pip install -r requirements.txt

# Optional: Add Gemini API key for LLM string analysis
echo "GEMINI_API_KEY=your_key_here" > .env

# Run
uvicorn app.main:app --reload --port 8000

# Test
pytest tests/ -v
```

## Docker

```bash
docker build -t sentinelx .
docker run -p 8000:8000 -e GEMINI_API_KEY=your_key sentinelx
```

## Example: Analyze a suspicious binary

```bash
curl -X POST http://localhost:8000/analyze/features \
  -H "Content-Type: application/json" \
  -d '{
    "file_entropy": 7.45,
    "num_sections": 3,
    "num_imports": 11,
    "suspicious_import_count": 8,
    "anti_debug_calls": 3,
    "has_packing_artifacts": 1,
    "pe_timestamp_anomaly": 1,
    "network_indicators": 5,
    ...
  }'
```

Response:
```json
{
  "scan_id": "A3F8C2D1",
  "threat_level": "MALICIOUS",
  "confidence_score": 0.891,
  "detection_path": "LLM_HEURISTIC",
  "generated_yara_rule": "rule SentinelX_AutoGen_A3F8C2D1 { ... }",
  "recommendation": "🔴 BLOCK immediately. Quarantine file and isolate endpoint."
}
```

## Project Structure

```
sentinelx/
├── app/
│   ├── main.py                  # FastAPI application
│   ├── schemas.py               # Pydantic models
│   ├── core/
│   │   ├── config.py            # Settings
│   │   ├── model_loader.py      # Model singleton
│   │   └── detection_engine.py  # YARA + GBM + LLM pipeline
│   └── routers/
│       ├── analyze.py           # /analyze endpoints
│       ├── benchmark.py         # /benchmark endpoints
│       ├── dataset.py           # /dataset endpoints
│       └── model.py             # /model endpoints
├── models/                      # Trained model artifacts (.pkl)
├── rules/                       # YARA rule files
├── data/                        # sentinelx_dataset.csv
├── tests/                       # pytest test suite (18 tests)
├── requirements.txt
└── Dockerfile
```

## Citation

```bibtex
@inproceedings{sentinelx2026,
  title     = {Malware Detection via Signature-Based Pattern Matching: 
               An Optimized Algorithmic Approach to Efficient Scanning},
  author    = {Sharath Kumar, K. and Archana, M. and Abhign Reddy, M. and Ananya, K.},
  booktitle = {CMR College of Engineering \& Technology},
  year      = {2026},
  note      = {SentinelX framework — YARA + Gemini Flash hybrid detection}
}
```
