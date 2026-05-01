from google import genai
import json
import time
import os

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

def generate_remediation(violation_code, control):
    """
    Takes one NRB control violation and generates
    a specific context-aware remediation recommendation.
    """
    prompt = f"""You are a DevSecOps security advisor helping a Nepali fintech startup
comply with Nepal Rastra Bank (NRB) ICT Security Guidelines.

A container image security scan found this violation:

VIOLATION CODE:  {violation_code}
NRB CLAUSE:      {control['nrb_clause']}
NRB DOCUMENT:    {control['nrb_document']}
NRB REQUIREMENT: {control['description']}
BASIC HINT:      {control['remediation_hint']}

Respond ONLY with a valid JSON object in exactly this format, no other text:
{{
  "immediate_fix": "one specific Dockerfile change to fix this",
  "code_example": "actual Dockerfile snippet showing the fix",
  "nrb_justification": "one sentence explaining how this fix satisfies the NRB clause",
  "risk_if_ignored": "what could go wrong specifically in a Nepal payment processing context"
}}"""

    try:
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        raw   = response.text.strip()
        clean = raw.replace("```json", "").replace("```", "").strip()
        return json.loads(clean)
    except json.JSONDecodeError:
        return {
            "immediate_fix":     "See remediation hint above",
            "code_example":      "Refer to NRB guidelines",
            "nrb_justification": control["remediation_hint"],
            "risk_if_ignored":   "Non-compliance with NRB ICT Security Guidelines"
        }
    except Exception as e:
        print(f"  [!] AI advisor error for {violation_code}: {e}")
        return None


def advise_all_violations(nrb_compliance):
    """
    Loop through all failed NRB controls and generate
    AI remediation advice for each violation found.
    """
    advisories = []
    failed_controls = [
        c for c in nrb_compliance["controls"]
        if not c["compliant"]
    ]

    if not failed_controls:
        print("  [*] No violations found - no AI advisories needed.")
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
            time.sleep(1)

    return advisories


def generate_executive_report(report_data):
    """
    Generate a plain-English NRB compliance narrative
    suitable for a startup CTO or NRB auditor.
    """
    nrb = report_data["nrb_compliance"]

    failed = [
        c["nrb_clause"]
        for c in nrb["controls"]
        if not c["compliant"]
    ]
    passed = [
        c["nrb_clause"]
        for c in nrb["controls"]
        if c["compliant"]
    ]

    summary = {
        "image_name":       report_data["image"],
        "compliance_score": nrb["compliance_score"],
        "critical_cves":    nrb["total_critical_cves"],
        "high_cves":        nrb["total_high_cves"],
        "medium_cves":      nrb["total_medium_cves"],
        "failed_controls":  failed,
        "passed_controls":  passed,
    }

    prompt = f"""You are a compliance officer writing a formal security assessment
report for a fintech startup regulated by Nepal Rastra Bank (NRB).

Automated container image scan results:
{json.dumps(summary, indent=2)}

Write a formal compliance assessment with exactly these five sections:

1. Executive Summary
Write 2-3 sentences in plain non-technical English summarising
the overall compliance status and whether this image is safe to deploy.

2. Compliance Status
Reference specific NRB clauses that passed and failed by name.

3. Key Risk Areas
Explain the top risks in business terms a CEO would understand.
Focus on what could go wrong for a Nepali payment processing company.

4. Recommended Actions
A prioritised list of actions, most critical first.
Be specific - name the actual fixes needed.

5. Conclusion
State clearly whether this container image meets NRB requirements
for deployment in a payment processing environment.

Write formally but clearly. Reference NRB clauses by name throughout."""

    try:
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        return response.text
    except Exception as e:
        print(f"  [!] Executive report generation error: {e}")
        return "Executive report could not be generated. Please check API key and connectivity."
