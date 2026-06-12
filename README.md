---

# Sentinel-X AI SOC Analyst

AI-powered Security Operations Center (SOC) platform for threat detection, asset exposure intelligence, risk assessment, and automated security reporting.

![Dashboard](Screenshots/dashboard-overview.png)

---

## Features

### Threat Analysis Engine

* Isolation Forest anomaly detection
* Random Forest threat classification
* MITRE ATT&CK technique mapping
* Threat severity scoring
* AI-generated analyst reports

### Asset Exposure Intelligence

* Live host and port scanning
* Exposure assessment
* Risk scoring
* Vulnerability reporting
* Asset inventory overview

### AI Security Reporting

* Google Gemini integration
* Executive security summaries
* SOC analyst explanations
* Incident impact assessment
* PDF report generation

### Interactive Security Dashboard

* Attack spike visualization
* Threat distribution analytics
* Top source IP tracking
* Target port analysis
* Model performance monitoring

---

## Technology Stack

### Frontend

* React
* TypeScript
* Vite
* Tailwind CSS

### Backend

* FastAPI
* Python
* Scikit-Learn
* Pandas
* Polars

### AI & Machine Learning

* Google Gemini
* Isolation Forest
* Random Forest
* Threat Intelligence Engine

---

## Architecture

```text
CSV Network Traffic
        │
        ▼
Data Processing
        │
        ▼
Isolation Forest
(Anomaly Detection)
        │
        ▼
Random Forest
(Classification)
        │
        ▼
Threat Intelligence
        │
        ▼
Gemini AI Analysis
        │
        ▼
SOC Dashboard & PDF Reports
```

---

## Screenshots

### Threat Analysis Dashboard

![Threat Analysis](Screenshots/dashboard-overview.png)

---

### Asset Exposure Intelligence

![Asset Scan](Screenshots/asset-scan-results.png)

---

### Asset Scan Results

![Asset Results](Screenshots/asset-scan-summary.png)

---

### Threat Visualization

![Charts](Screenshots/threat-analysis-charts.png)

---

### Threat Investigation Table

![Table](Screenshots/threat-analysis-table.png)

---

## Installation

### Clone Repository

```bash
git clone https://github.com/irfanahmed0019/sentinel-x-ai-soc-analyst.git
cd sentinel-x-ai-soc-analyst
```

---

### Backend Setup

```bash
cd backend

pip install -r requirements.txt

uvicorn main:app --reload
```

Backend runs at:

```text
http://localhost:8000
```

---

### Frontend Setup

```bash
cd frontend

npm install

npm run dev
```

Frontend runs at:

```text
http://localhost:5173
```

---

## Machine Learning Pipeline

### Isolation Forest

Used for:

* Unsupervised anomaly detection
* Unknown threat discovery
* Behavioral deviation analysis

### Random Forest

Used for:

* Threat classification
* Risk prediction
* Attack categorization

---

## Example Detection Results

| Metric             | Value     |
| ------------------ | --------- |
| Records Analyzed   | 2,520,751 |
| Highest Risk Score | 83        |
| Medium Risk Events | 321,833   |
| High Risk Events   | 13,116    |
| Most Common Attack | DDoS      |

---

## Future Improvements

* Docker deployment
* Real-time packet capture
* SIEM integration
* Threat intelligence feeds
* Multi-user authentication
* SOC case management
* Kubernetes deployment

---

## Author

**Irfan Ahmed**

GitHub:
[https://github.com/irfanahmed0019](https://github.com/irfanahmed0019)

---

## License

MIT License

---
