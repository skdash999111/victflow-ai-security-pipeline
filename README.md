# VictFlow AI Security, Red Teaming & Runtime Firewall Pipeline

An end-to-end, zero-cost **AI Red Teaming, SARIF Triage & Runtime Guardrail Pipeline** built to evaluate Large Language Models (LLMs) against adversarial attacks, standardize findings into **SARIF v2.1.0**, enrich alerts via local AI triage, and enforce real-time input/output defenses via an OpenAI-compatible FastAPI security gateway.

Engineered to integrate seamlessly with existing **SAST (Semgrep)**, **SCA (Trivy)**, and **DAST (OWASP ZAP)** DevSecOps reporting dashboards.

---

## Closed-Loop Architecture

```text
                    ┌───────────────────────────────────────────┐
                    │         1. ADVERSARIAL RED TEAMING        │
                    │  NVIDIA Garak (probes.encoding.InjectB64) │
                    └─────────────────────┬─────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │         2. SARIF & LOCAL AI TRIAGE        │
                    │  garak_to_sarif.py ──▶ ai_sarif_triage.py │
                    │  (OWASP LLM / CWE + Local Qwen 2.5 JSON)  │
                    └─────────────────────┬─────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │    3. RUNTIME AI FIREWALL MICROSERVICE    │
                    │  firewall_server.py (FastAPI :8000/v1)    │
                    │  • Base64 Payload Decoder                 │
                    │  • Protect AI DeBERTa-v3 Injection Filter │
                    │  • Regex Secret & Exfiltration Scrubber   │
                    └─────────────────────┬─────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │       4. TARGET INFERENCE ENGINE          │
                    │       Ollama Local LLM (qwen2.5:3b)       │
                    └───────────────────────────────────────────┘
