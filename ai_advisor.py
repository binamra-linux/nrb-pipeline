import json
import time
import urllib.request
import os

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"

def call_ollama(prompt, timeout=180):
    """Call local Ollama model."""
    payload = json.dumps({
        "model":   OLLAMA_MODEL,
        "prompt":  prompt,
        "stream":  False,
        "options": {"temperature": 0.3, "num_predict": 512}
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result.get("response", "").strip()
    except Exception as e:
        print(f"      [!] Ollama error: {e}")
        return None


def generate_remediation(violation_code, control):
    """Generate NRB-specific remediation advice for one violation."""
    prompt = f"""DevSecOps advisor for Nepal Rastra Bank (NRB) compliance.

Violation: {violation_code}
NRB Clause: {control['nrb_clause']}
Requirement: {control['description']}

Reply with ONLY this JSON, no other text:
{{
  "immediate_fix": "one Dockerfile change to fix this",
  "code_example": "Dockerfile snippet",
  "nrb_justification": "one sentence linking fix to NRB clause",
  "risk_if_ignored": "business risk for Nepal payment processor"
}}"""

    try:
        raw = call_ollama(prompt, timeout=120)
        if not raw:
            raise Exception("No response")
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start == -1 or end == 0:
            raise ValueError("No JSON in response")
        return json.loads(raw[start:end])
    except Exception:
        return {
            "immediate_fix":     control["remediation_hint"],
            "code_example":      "# See NRB remediation guidance",
            "nrb_justification": f"Addresses {control['nrb_clause']}",
            "risk_if_ignored":   "Non-compliance with NRB ICT Security Guidelines"
        }


def advise_all_violations(nrb_compliance):
    """Generate AI remediation advice for every failed NRB control."""
    advisories      = []
    failed_controls = [
        c for c in nrb_compliance["controls"] if not c["compliant"]
    ]

    if not failed_controls:
        print("  [*] No violations found.")
        return advisories

    print(f"  [*] Generating AI advice for {len(failed_controls)} failed controls...")

    for control in failed_controls:
        for violation_code in control["violations"]:
            print(f"      - Advising on {control['id']}: {violation_code}")
            advisory = generate_remediation(violation_code, control)
            if advisory:
                advisories.append({
                    "nrb_id":       control["id"],
                    "nrb_clause":   control["nrb_clause"],
                    "nrb_document": control["nrb_document"],
                    "violation":    violation_code,
                    "advisory":     advisory,
                })

    return advisories


def generate_executive_report(report_data):
    """Generate short NRB compliance narrative."""
    nrb    = report_data["nrb_compliance"]
    failed = [c["nrb_clause"] for c in nrb["controls"] if not c["compliant"]]
    passed = [c["nrb_clause"] for c in nrb["controls"] if c["compliant"]]

    prompt = f"""Write a short NRB compliance report for a Nepali fintech startup.

Image: {report_data["image"]}
NRB Compliance Score: {nrb["compliance_score"]}%
Critical CVEs: {nrb["total_critical_cves"]}
High CVEs: {nrb["total_high_cves"]}
Failed NRB Controls: {", ".join(failed[:5])}
Passed NRB Controls: {", ".join(passed[:5])}

Write 4 short sections: Executive Summary, Key Risks, Top 3 Actions, Conclusion.
Be concise. Max 200 words total."""

    text = call_ollama(prompt, timeout=180)
    return text if text else "Executive report could not be generated."
