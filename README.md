# SentinelX — Explainable Cyber Threat Correlation & Response Platform

A Streamlit prototype for security event exploration, deterministic detection rules, evidence-linked alert explanations, investigation storylines, response checklists, and JSON/CSV exports.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Render

1. Push `app.py`, `requirements.txt`, and `Procfile` to a GitHub repository.
2. In Render, create a **Web Service** connected to the repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`
5. Deploy and test the generated public URL.

## CSV schema
Required: `timestamp,username,source_ip,event,status`
Optional: `asset,details`

Download the in-app sample CSV for an example.

## Prototype scope and limitations
- Uses deterministic, explainable rules rather than an ML model.
- No live SIEM integration, external threat-intelligence API, or automatic blocking.
- Risk scores are heuristic prioritization values, not probabilities.
- Correlation suggests a sequence; it does not prove compromise or attribution.
- Use synthetic data or logs you are authorized to process.

## Suggested evaluation
Create a labelled synthetic test set with expected detections. Report precision, recall, false positives, and processing time. Compare independent alerts against the evidence-linked storyline and next-validation workflow. Do not claim novelty until the exact feature set has been compared with relevant existing tools.
