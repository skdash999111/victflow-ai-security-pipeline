import json
import requests
from pathlib import Path

def triage_finding_local(rule_id: str, level: str, message: str, location_uri: str) -> dict:
    prompt = f"""You are a Principal Application & AI Security Engineer.
Analyze this SARIF security finding and return ONLY valid JSON with exact keys:
- "verdict": "TRUE_POSITIVE" | "LIKELY_FALSE_POSITIVE" | "NEEDS_MANUAL_REVIEW"
- "risk_summary": "1-sentence plain-English security impact"
- "remediation_steps": "Concrete code or guardrail fix to resolve this issue"

Finding Details:
- Rule ID: {rule_id}
- Severity: {level}
- Target/File: {location_uri}
- Scanner Message: {message}
"""
    payload = {
        "model": "qwen2.5:3b",
        "messages": [{"role": "user", "content": prompt}],
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.1}
    }
    resp = requests.post("http://127.0.0.1:11434/api/chat", json=payload, timeout=60)
    resp.raise_for_status()
    return json.loads(resp.json()["message"]["content"])

def enrich_sarif_report(input_sarif_path: str, output_sarif_path: str) -> None:
    sarif_data = json.loads(Path(input_sarif_path).read_text(encoding="utf-8"))
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "UNKNOWN")
            level = result.get("level", "warning")
            message = result.get("message", {}).get("text", "")
            locs = result.get("locations", [{}])
            uri = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "unknown")

            triage = triage_finding_local(rule_id, level, message, uri)
            result.setdefault("properties", {})
            result["properties"]["ai_triage_verdict"] = triage.get("verdict")
            result["properties"]["ai_risk_summary"] = triage.get("risk_summary")
            result["properties"]["ai_remediation"] = triage.get("remediation_steps")
            result["message"]["text"] += (
                f"\n\n[AI Triage: {triage.get('verdict')}] "
                f"Impact: {triage.get('risk_summary')} | "
                f"Fix: {triage.get('remediation_steps')}"
            )
    Path(output_sarif_path).write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")

if __name__ == "__main__":
    enrich_sarif_report("garak_ai_findings.sarif", "triaged_findings.sarif")
