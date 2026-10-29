# Glossary

| Term | Full form / meaning |
| --- | --- |
| **TCB** | Trusted Computing Base — code/data that must stay correct even under attack (here: policy + reference monitor + invariants) |
| **Reference monitor** | Component that checks every request against the security policy (approve or deny) |
| **RBAC** | Role-Based Access Control — permissions granted by role/task (e.g. researcher vs ops) |
| **IFC** | Information-Flow Control — tracking/restricting where sensitive data may flow |
| **LLM** | Large Language Model — the AI model driving the agent (treated as untrusted) |
| **PI** | Prompt Injection — malicious instructions in data (email, web, files) that steer the agent |
| **ASR** | Attack Success Rate — share of attack steps that were **allowed** (lower is better) |
| **TPR** | True Positive Rate — share of attacks correctly **blocked** (also called recall / containment here) |
| **FPR** | False Positive Rate — share of benign steps wrongly **blocked** (false-block rate) |
| **TP / FP / TN / FN** | True Positive / False Positive / True Negative / False Negative — confusion-matrix counts for allow/deny |
| **F1** | Harmonic mean of precision and recall — balances “when we block, are we right?” and “did we catch attacks?” |
| **MCP** | Model Context Protocol — standard for connecting agents to external tools/servers |
| **A2A** | Agent-to-Agent — one agent messaging or steering another |
| **DNS** | Domain Name System — name→IP lookup; abused to sneak data out in query names |
| **PII** | Personally Identifiable Information — e.g. email, SSN, passport-like data |
| **DLP** | Data Loss Prevention — controls that stop sensitive data leaving authorized destinations |
| **RCE** | Remote Code Execution — attacker causes code to run on the host |
| **XSS** | Cross-Site Scripting — injecting script into a web page viewed by a victim |
| **ANSI (escapes)** | Control sequences in terminal output that can manipulate display/clipboard |
| **CVE** | Common Vulnerabilities and Exposures — public vulnerability ID scheme |
| **OWASP** | Open Worldwide Application Security Project — community that tracks web/agent security risks |
| **CERT-In** | Indian Computer Emergency Response Team — India’s national cyber incident agency |
| **CRM** | Customer Relationship Management — business system holding customer records |
| **API** | Application Programming Interface — programmatic service endpoint (often needs keys) |
| **HTTP / HTTPS** | Hypertext Transfer Protocol (Secure) — web request protocols |
| **p50 / p95** | 50th / 95th percentile — latency points (median and high-tail) |
| **EXTERNAL** | Trust level for untrusted channels (web, tickets, tool output) — treated as data, not instructions |

---

