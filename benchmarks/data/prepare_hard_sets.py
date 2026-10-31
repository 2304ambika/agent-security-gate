#!/usr/bin/env python3
"""Build curated hard subsets under benchmarks/external/prepared/."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

EXT = Path(__file__).resolve().parent / "external"
PREP = EXT / "prepared"


def main() -> None:
    PREP.mkdir(parents=True, exist_ok=True)

    lakera_csv = EXT / "lakera_b3" / "selected_attacks_low-quality.csv"
    if lakera_csv.exists():
        rows = list(csv.DictReader(lakera_csv.open(encoding="utf-8")))
        l2 = [r for r in rows if r.get("level") == "2"]
        priority = {
            "legal_TI_exfiltration",
            "email_tool_invocation",
            "product_recommendation_tool_extraction",
            "mcp_chat_poisoning",
            "code_review_malicious",
            "trip_planner_phishing",
        }
        hard = sorted(
            l2,
            key=lambda r: (0 if r.get("app_slug") in priority else 1, -len(r.get("attack") or "")),
        )
        (PREP / "lakera_l2_hard.jsonl").write_text(
            "\n".join(json.dumps(r) for r in hard) + "\n", encoding="utf-8"
        )
        print(f"lakera_l2_hard: {len(hard)}")

    a3_path = EXT / "a3s" / "injected.json"
    if a3_path.exists():
        a3 = json.loads(a3_path.read_text(encoding="utf-8"))
        hard_risk = {
            "Dangerous Command Execution",
            "Data Exfiltration",
            "Privilege Escalation",
            "Sandbox Escape",
            "Information Leakage",
            "Configuration Tampering",
            "Jailbreak Attack",
        }
        hard = []
        for r in a3:
            if r.get("risk_category") not in hard_risk:
                continue
            inj = [
                t
                for t in (r.get("turns") or [])
                if t.get("injection_in_tool") or t.get("injection_in_user")
            ]
            if not inj:
                continue
            hard.append(
                {
                    "id": r.get("id"),
                    "name": r.get("name"),
                    "risk_category": r.get("risk_category"),
                    "technique": r.get("technique"),
                    "scenario": r.get("scenario"),
                    "description": r.get("description"),
                    "turns": inj[:4],
                }
            )

        def score(x: dict) -> tuple:
            tool_inj = sum(1 for t in x["turns"] if t.get("injection_in_tool"))
            risk_w = {
                "Data Exfiltration": 5,
                "Privilege Escalation": 5,
                "Sandbox Escape": 5,
                "Dangerous Command Execution": 4,
                "Information Leakage": 3,
                "Configuration Tampering": 3,
                "Jailbreak Attack": 2,
            }.get(x["risk_category"], 1)
            return (-risk_w, -tool_inj, -len(x.get("description") or ""))

        hard = sorted(hard, key=score)[:200]
        (PREP / "a3s_hard200.jsonl").write_text(
            "\n".join(json.dumps(r) for r in hard) + "\n", encoding="utf-8"
        )
        print(f"a3s_hard200: {len(hard)} {Counter(r['risk_category'] for r in hard)}")

    inj = []
    for split, name in (
        ("dh", "test_cases_dh_enhanced.json"),
        ("ds", "test_cases_ds_enhanced.json"),
    ):
        path = EXT / "injecagent" / name
        if not path.exists():
            continue
        for i, row in enumerate(json.loads(path.read_text(encoding="utf-8"))):
            inj.append(
                {
                    "id": f"injec-{split}-{i}",
                    "split": split,
                    "attack_type": row.get("Attack Type"),
                    "user_tool": row.get("User Tool"),
                    "user_instruction": row.get("User Instruction"),
                    "attacker_tools": row.get("Attacker Tools"),
                    "attacker_instruction": row.get("Attacker Instruction"),
                    "tool_response": row.get("Tool Response"),
                    "expected_achievements": row.get("Expected Achievements"),
                }
            )

    if inj:

        def iscore(x: dict) -> int:
            w = 3 if x["split"] == "ds" else 1
            at = (x.get("attack_type") or "").lower()
            if "data" in at or "financ" in at or "exfil" in at:
                w += 3
            if "harm" in at:
                w += 1
            return -w

        hard = sorted(inj, key=iscore)[:300]
        (PREP / "injecagent_hard300.jsonl").write_text(
            "\n".join(json.dumps(r) for r in hard) + "\n", encoding="utf-8"
        )
        print(f"injecagent_hard300: {len(hard)}")

    ah_path = EXT / "agentharm" / "harmful_behaviors_test_public.json"
    if ah_path.exists():
        ah = json.loads(ah_path.read_text(encoding="utf-8"))
        keep = [
            b
            for b in ah.get("behaviors", [])
            if b.get("category") in {"Cybercrime", "Fraud", "Harassment"}
        ]
        (PREP / "agentharm_toolish.jsonl").write_text(
            "\n".join(json.dumps(b) for b in keep) + "\n", encoding="utf-8"
        )
        print(f"agentharm_toolish: {len(keep)}")


if __name__ == "__main__":
    main()
