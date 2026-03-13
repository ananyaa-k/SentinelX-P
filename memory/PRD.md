# SentinelX Defender - Product Requirements Document

## Project Overview
**Name:** SentinelX Defender  
**Version:** 2.0  
**Type:** Cybersecurity Dashboard - Malware Detection & Threat Intelligence  
**Created:** March 2026

## Original Problem Statement
Build a full-stack cybersecurity dashboard called "SentinelX Defender" — a malware detection and threat intelligence interface with:
- Light "Technical Minimalist" theme (Paper #F7F7F5 / Forest #1A3C2B)
- Admin authentication for restricted routes
- File scanner with feature vector analysis
- Benchmark comparisons between detection approaches
- Dataset explorer
- Model intelligence visualization

## User Personas

### 1. Security Analyst (Primary)
- Needs quick malware analysis
- Uses scanner for PE file feature analysis
- Reviews threat levels and recommendations

### 2. SOC Administrator
- Access to benchmark metrics
- Reviews dataset statistics
- Monitors model performance
- Manages system configuration

## Core Requirements (Static)

### Functional
- [x] Dashboard with system status and recent scans
- [x] File scanner with 20-field feature vector form
- [x] Threat analysis with confidence scores
- [x] YARA rule matching and generation
- [x] LLM-based behavioral analysis
- [x] Benchmark comparison (3-way: YARA, Basic-ML, SentinelX)
- [x] Dataset explorer with filtering/pagination
- [x] Model architecture visualization
- [x] Admin authentication with JWT

### Non-Functional
- [x] Light "Technical Minimalist" design
- [x] Space Grotesk + JetBrains Mono typography
- [x] Responsive design (desktop, tablet, mobile)
- [x] No shadows, 0-2px border-radius
- [x] 1px hairline borders

## What's Been Implemented (March 2026)

### Backend (FastAPI)
- `/api/health` - System health status
- `/api/stats` - Dashboard statistics
- `/api/analyze/features` - Malware feature analysis
- `/api/admin/login` - JWT authentication
- `/api/admin/verify` - Token verification
- `/api/benchmark/results` - Static benchmark data
- `/api/benchmark/run` - Live benchmark execution
- `/api/dataset/info` - Dataset statistics
- `/api/dataset/samples` - Paginated sample data
- `/api/model/explain` - Feature importance
- `/api/model/info` - Model architecture
- `/api/scans/recent` - Recent scan history

### Frontend (React)
- **Dashboard (/)** - Public - Stats, system status, recent scans
- **Scanner (/scanner)** - Public - Feature vector analysis
- **Benchmark (/benchmark)** - Admin - 3-way comparison charts
- **Dataset (/dataset)** - Admin - Sample explorer
- **Model (/model)** - Admin - Architecture diagram
- **Admin Login (/admin/login)** - Authentication

### Design System
- Colors: Paper (#F7F7F5), Forest (#1A3C2B), Coral (#FF8C69), Mint (#9EFFBF), Gold (#F4D35E)
- Fonts: Space Grotesk (headings), JetBrains Mono (technical)
- Components: Shadcn UI with custom overrides
- Charts: Recharts (Bar, Pie, Scatter)

## Authentication
- **Demo Credentials:** admin@sentinelx.io / sentinel2024
- **Token:** JWT with 24-hour expiry
- **Protected Routes:** /benchmark, /dataset, /model

## Prioritized Backlog

### P0 (Critical) - Done
- [x] Core malware analysis functionality
- [x] Admin authentication
- [x] Basic dashboard and scanner

### P1 (High Priority) - Future
- [ ] Real file upload with PE parsing
- [ ] Actual ML model integration
- [ ] YARA rule execution engine
- [ ] Scan history persistence
- [ ] Export reports to PDF

### P2 (Medium Priority) - Future
- [ ] Multi-user support with roles
- [ ] Real-time threat feed integration
- [ ] Custom YARA rule management
- [ ] Email alerts for high-threat detections
- [ ] API rate limiting

### P3 (Low Priority) - Future
- [ ] Dark theme toggle
- [ ] Dashboard customization
- [ ] Bulk file scanning
- [ ] Integration with VirusTotal API

## Tech Stack
- **Frontend:** React, Tailwind CSS, Shadcn UI, Recharts
- **Backend:** FastAPI, MongoDB, PyJWT
- **Deployment:** Kubernetes (Emergent Platform)

## Next Action Items
1. Implement real file upload with PE file parsing
2. Integrate actual ML model for classification
3. Add scan history persistence to MongoDB
4. Create PDF report generation
5. Add real-time threat feed integration
