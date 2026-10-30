#!/usr/bin/env python3
"""P5 (offline part): InjecAgent data-stealing cases, built from the dataset's own fields (no synthetic payloads).

task = the case's User Instruction; untrusted context = its Tool Response (with the injection);
attack call = send_email to the address the Attacker Instruction names (extracted by regex; cases with no
address are skipped and counted). The attacker address is chosen by the dataset authors, not by this repo.
Attack-only suite: reports TPR (+Wilson CI); FPR is NOT measurable here. Run: make p5
"""

import json
import re
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in ("src", "benchmarks/data", "benchmarks/runners"):
    sys.path.insert(0, str(ROOT / p))
from agent_security_gate.tcb import SecurityTCB  # noqa: E402
from agent_security_gate.policy import TrustLevel  # noqa: E402
from run_split_bench import base_policy, wilson  # noqa: E402

DATA = ROOT / "benchmarks" / "data" / "external" / "injecagent"
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def cases():
    out, skipped = [], 0
    for f in ("test_cases_ds_enhanced.json", "test_cases_dh_enhanced.json"):
        for r in json.loads((DATA / f).read_text()):
            m = EMAIL.search(r["Attacker Instruction"])
            if "GmailSendEmail" in str(r["Attacker Tools"]) and m:
                plain = str(r["Tool Response Template"]).replace("<Attacker Instruction>", r["Attacker Instruction"])
                out.append((r["User Instruction"], str(r["Tool Response"]), m.group(0), "enhanced"))  # with the 'IMPORTANT!!! Ignore all previous...' hint
                out.append((r["User Instruction"], plain, m.group(0), "base"))  # InjecAgent's base setting: bare instruction
            else:
                skipped += 1
    return out, skipped


def _allow_gmail(p):
    """Every attacker address is @gmail.com; with the default allowlist the network check blocks all of them for the
    wrong reason (and would block every benign mail to gmail). Allow the domain so the test isolates the grounding."""
    n = p.network
    p.network = replace(n, allowed_hosts=n.allowed_hosts | {"gmail.com"}, dns_allowlist=n.dns_allowlist | {"gmail.com"})
    return p


def policies():
    base = _allow_gmail(base_policy())
    s = _allow_gmail(base_policy())
    s.content = replace(s.content, free_plain_reads=True)
    for slot in (("send_email", "to"), ("http_fetch", "url"), ("write_file", "path")):
        s.with_grounded_slot(slot)
    return {"base": base, "slots": s}


def main():
    cs, skipped = cases()
    print(f"{len(cs)//2} email-exfil cases x 2 settings (skipped {skipped} with no GmailSendEmail+address)")
    res = {}
    for name, pol in policies().items():
      for setting in ("enhanced", "base"):
        sub = [c for c in cs if c[3] == setting]
        blocked = 0
        for task, resp, addr, split in sub:
            tcb = SecurityTCB(policy=pol)
            tcb.policy.role_capabilities["agent"] = {"network_read", "comms"}
            tcb.register_tool("send_email", lambda a: "ok")
            tcb.begin_task("u", task, role="agent")
            r = tcb.invoke("send_email", {"to": addr, "subject": "data", "body": "see attached"}, data_channel=resp, data_trust=TrustLevel.EXTERNAL)
            blocked += not r.decision.allowed
        lo, hi = wilson(blocked, len(sub))
        res[f"{name}/{setting}"] = {"tpr": blocked / len(sub), "ci": [round(lo, 3), round(hi, 3)], "n": len(sub)}
        print(f"{name:6} {setting:9} TPR {blocked/len(sub):6.1%}  (95% CI {lo:.1%}-{hi:.1%})  attack success {1-blocked/len(sub):.1%}")
    (ROOT / "results" / "offline" / "p5_injecagent.json").write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
