# victflow-ai-security-pipeline
Automated LLM Red Teaming (NVIDIA Garak) and Local AI-Powered SARIF v2.1.0 Vulnerability Triage Engine
# VictFlow AI Security & SARIF Triage Pipeline

An automated, zero-cost **AI Red Teaming & DevSecOps Triage Pipeline** designed to evaluate Large Language Model (LLM) endpoints for adversarial vulnerabilities, standardize findings into **SARIF v2.1.0**, and enrich security alerts using local structured-JSON AI triage.

Built to extend unified **SAST (Semgrep)**, **SCA (Trivy)**, and **DAST (OWASP ZAP)** application security workflows into Generative AI and RAG systems.

---

## Architecture & Data Flow

```text
┌─────────────────────┐      ┌──────────────────────┐      ┌──────────────────────────┐
│  Target LLM / RAG   │─────▶│    NVIDIA Garak      │─────▶│    garak_to_sarif.py     │
│  (Ollama / OpenAI)  │      │  (Adversarial Probes)│      │ (OWASP LLM / CWE Mapper) │
└─────────────────────┘      └──────────────────────┘      └────────────┬─────────────┘
                                                                        │
                                                                        ▼
┌─────────────────────┐      ┌──────────────────────┐      ┌──────────────────────────┐
│  VictFlow Unified   │◀─────│ triaged_findings.sarif│◀─────│   ai_sarif_triage.py     │
│   Audit Dashboard   │      │ (Enriched JSON Schema)│      │ (Local LLM Risk Triage)  │
└─────────────────────┘      └──────────────────────┘      └──────────────────────────┘
