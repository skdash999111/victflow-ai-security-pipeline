import json
import glob
import sys
from pathlib import Path
from typing import Any, Dict, List

PROBE_TAXONOMY: Dict[str, Dict[str, str]] = {
    "promptinject": {
        "owasp": "LLM01:2025 Prompt Injection",
        "cwe": "CWE-1427",
        "description": "Model susceptible to direct or indirect prompt injection overriding system instructions."
    },
    "dan": {
        "owasp": "LLM01:2025 Prompt Injection",
        "cwe": "CWE-1427",
        "description": "Model bypassed safety boundaries via roleplay/jailbreak persona framing."
    },
    "encoding": {
        "owasp": "LLM01:2025 Prompt Injection",
        "cwe": "CWE-1427",
        "description": "Model executed obfuscated instructions (Base64/Hex/ROT13) bypassing input filters."
    },
    "leakreplay": {
        "owasp": "LLM02:2025 Sensitive Information Disclosure",
        "cwe": "CWE-200",
        "description": "Model leaked memorized training data or sensitive context."
    },
    "xss": {
        "owasp": "LLM05:2025 Improper Output Handling",
        "cwe": "CWE-79",
        "description": "Model emitted unescaped HTML/JavaScript payloads capable of triggering downstream XSS."
    }
}

DEFAULT_TAXONOMY = {
    "owasp": "LLM05:2025 Improper Output Handling",
    "cwe": "CWE-1426",
    "description": "Generative AI model failed automated adversarial probe evaluation."
}

def extract_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, list) and payload:
        return extract_text(payload[-1])
    if isinstance(payload, dict):
        if "text" in payload:
            return str(payload["text"])
        if "content" in payload:
            return str(payload["content"])
        if "turns" in payload and payload["turns"]:
            return extract_text(payload["turns"][-1])
    return str(payload)

def map_severity(vulnerability_rate: float) -> str:
    if vulnerability_rate >= 50.0:
        return "error"
    if vulnerability_rate > 0.0:
        return "warning"
    return "note"

def convert_garak_to_sarif(report_path: str, output_path: str) -> None:
    target_model = "unknown-llm"
    garak_version = "0.17.x"
    eval_entries: List[Dict[str, Any]] = []
    sample_failures: Dict[str, Dict[str, str]] = {}

    with open(report_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            entry_type = record.get("entry_type")

            if entry_type == "start_run setup":
                target_model = record.get("plugins.model_name", target_model)
                garak_version = record.get("_config.version", garak_version)
            elif entry_type == "attempt" and record.get("status") == 2:
                probe_name = record.get("probe_classname", "")
                if probe_name and probe_name not in sample_failures:
                    detector_results = record.get("detector_results", {})
                    is_hit = any(
                        (max(scores) > 0.5 if isinstance(scores, list) and scores else float(scores) > 0.5)
                        for scores in detector_results.values()
                    )
                    if is_hit:
                        prompt_txt = extract_text(record.get("prompt", ""))[:300]
                        output_txt = extract_text(record.get("outputs", [""])[0])[:300]
                        sample_failures[probe_name] = {
                            "prompt": prompt_txt,
                            "output": output_txt
                        }
            elif entry_type == "eval":
                eval_entries.append(record)

    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    seen_rules = set()

    for entry in eval_entries:
        probe = entry.get("probe", "unknown.Probe")
        detector = entry.get("detector", "unknown.Detector")
        passed = entry.get("passed", 0)
        total = entry.get("total_evaluated", entry.get("total", 0))

        if total == 0:
            continue

        failed_count = total - passed
        if failed_count <= 0:
            continue

        vuln_rate = round((failed_count / total) * 100.0, 2)
        level = map_severity(vuln_rate)
        family = probe.split(".")[0].lower()
        taxonomy = PROBE_TAXONOMY.get(family, DEFAULT_TAXONOMY)
        rule_id = f"GARAK-{probe}"

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": probe.replace(".", "_"),
                "shortDescription": {"text": f"LLM Vulnerability: {probe} ({taxonomy['owasp']})"},
                "fullDescription": {"text": taxonomy["description"]},
                "helpUri": f"https://reference.garak.ai/en/latest/garak.probes.{family}.html",
                "properties": {
                    "tags": ["AI-Security", "LLM-RedTeam", taxonomy["owasp"], taxonomy["cwe"]],
                    "security-severity": "8.5" if level == "error" else "5.5"
                }
            })

        evidence = sample_failures.get(probe, {})
        evidence_note = ""
        if evidence:
            evidence_note = (
                f" | Sample Trigger Prompt: \"{evidence['prompt']}\" "
                f"-> Model Output: \"{evidence['output']}\""
            )

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": (
                    f"[{taxonomy['owasp']}] Probe '{probe}' (detector: {detector}) breached "
                    f"{failed_count}/{total} attempts ({vuln_rate}% attack success rate) on model '{target_model}'."
                    f"{evidence_note}"
                )
            },
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": f"llm://endpoint/{target_model}"}}}
            ],
            "properties": {
                "scanner": "NVIDIA Garak",
                "category": "AI / LLM Security",
                "owasp_llm": taxonomy["owasp"],
                "cwe": taxonomy["cwe"],
                "passed": passed,
                "failed": failed_count,
                "total_evaluated": total,
                "attack_success_rate_pct": vuln_rate
            }
        })

    sarif_log = {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NVIDIA Garak (VictFlow AI Audit)",
                        "version": str(garak_version),
                        "informationUri": "https://github.com/NVIDIA/garak",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    }

    Path(output_path).write_text(json.dumps(sarif_log, indent=2), encoding="utf-8")
    print(f"[+] Converted {len(results)} failed AI security probes into SARIF v2.1.0 -> {output_path}")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        input_jsonl = sys.argv[1]
    else:
        matches = sorted(glob.glob("/root/.local/share/garak/garak_runs/*.report.jsonl"))
        if not matches:
            raise FileNotFoundError("No Garak .report.jsonl files found. Run your Garak scan cell first.")
        input_jsonl = matches[-1]

    output_sarif = sys.argv[2] if len(sys.argv) >= 3 else "garak_ai_findings.sarif"
    convert_garak_to_sarif(input_jsonl, output_sarif)
