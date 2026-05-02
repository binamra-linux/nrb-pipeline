import subprocess
import json
import sys
import os
from datetime import datetime

def run_trivy(image_name):
    """Run Trivy CVE scan on a Docker image."""
    print(f"  [*] Running Trivy CVE scan on {image_name}...")
    output_file = f"results/trivy_{image_name}.json"
    subprocess.run(
        ["trivy", "image", "--format", "json", "--output", output_file, 
         "--timeout", "5m", image_name],
        capture_output=True, text=True
    )
    try:
        with open(output_file) as f:
            return json.load(f)
    except Exception as e:
        print(f"  [!] Trivy error: {e}")
        return {"Results": []}

def run_hadolint(dockerfile_path):
    """Run Hadolint Dockerfile linter."""
    if not dockerfile_path:
        print(f"  [*] Skipping Hadolint (no Dockerfile available for pulled image)")
        return []
    print(f"  [*] Running Hadolint on {dockerfile_path}...")
    result = subprocess.run(
        ["hadolint", "--format", "json", dockerfile_path],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout) if result.stdout.strip() else []
    except Exception as e:
        print(f"  [!] Hadolint error: {e}")
        return []

def run_dockle(image_name):
    """Run Dockle CIS Docker Benchmark checks."""
    import re
    print(f"  [*] Running Dockle CIS checks on {image_name}...")
    result = subprocess.run(
        ["dockle", "--format", "json", image_name],
        capture_output=True, text=True
    )
    output = (result.stdout + result.stderr).strip()
    json_match = re.search(r'\{.*\}', output, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except Exception as e:
            print(f"  [!] Dockle parse error: {e}")
    print(f"  [!] Dockle returned no parseable JSON for {image_name}")
    return {"details": [], "summary": []}

def extract_cve_summary(trivy_data):
    """Count CVEs by severity from Trivy results."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    all_vulns = []
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
            all_vulns.append({
                "id":          vuln.get("VulnerabilityID", ""),
                "package":     vuln.get("PkgName", ""),
                "severity":    sev,
                "title":       vuln.get("Title", ""),
                "fixed_version": vuln.get("FixedVersion", "Not available")
            })
    return counts, all_vulns

def run_pipeline(image_name, dockerfile_path):
    """Run the full NRB compliance pipeline for one image."""
    print(f"\n{'='*60}")
    print(f" SCANNING: {image_name}")
    print(f"{'='*60}")

    os.makedirs("results", exist_ok=True)

    # Run all three tools
    trivy_data    = run_trivy(image_name)
    hadolint_data = run_hadolint(dockerfile_path)
    dockle_data   = run_dockle(image_name)

    # Summarise CVEs
    cve_counts, cve_list = extract_cve_summary(trivy_data)

    # Import mapper and AI modules
    from nrb_mapper import map_to_nrb
    from ai_advisor import advise_all_violations, generate_executive_report

    # Run NRB mapping
    print(f"  [*] Mapping findings to NRB controls...")
    nrb_compliance = map_to_nrb(trivy_data, hadolint_data, dockle_data)

    # Run AI advisor
    print(f"  [*] Generating AI remediation advisories...")
    ai_advisories = advise_all_violations(nrb_compliance)

    # Assemble full report data
    report_data = {
        "image":          image_name,
        "scan_time":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cve_counts":     cve_counts,
        "cve_list":       cve_list[:20],
        "hadolint":       hadolint_data,
        "dockle":         dockle_data,
        "nrb_compliance": nrb_compliance,
        "ai_advisories":  ai_advisories,
    }

    # Generate AI executive narrative
    print(f"  [*] Generating AI executive compliance narrative...")
    report_data["ai_narrative"] = generate_executive_report(report_data)

    # Save raw JSON for reference
    raw_output = f"results/raw_{image_name}.json"
    with open(raw_output, "w") as f:
        json.dump(report_data, f, indent=2)

    # Generate HTML dashboard
    from report_generator import generate_report
    generate_report(report_data)

    score = nrb_compliance["compliance_score"]
    print(f"\n  [+] Done. NRB Compliance Score: {score}%")
    print(f"  [+] Report saved to results/report_{image_name}.html")
    return report_data

if __name__ == "__main__":
    # Define all test images
    # None = no Dockerfile available (pulled from Docker Hub)
    images = [
        # Simulated images (controlled baseline)
        ("fintech-bad",          "fintech-apps/bad/Dockerfile"),
        ("fintech-medium",       "fintech-apps/medium/Dockerfile"),
        ("fintech-good",         "fintech-apps/good/Dockerfile"),
        # Real-world Docker Hub images
        ("fireflyiii/core",      None),
        ("akaunting/akaunting",  None),
    ]

    all_results = []
    for image_name, dockerfile in images:
        result = run_pipeline(image_name, dockerfile)
        all_results.append({
            "image":            image_name,
            "compliance_score": result["nrb_compliance"]["compliance_score"],
            "critical_cves":    result["cve_counts"]["CRITICAL"],
            "high_cves":        result["cve_counts"]["HIGH"],
        })

    # Print summary comparison table
    print(f"\n{'='*60}")
    print(" SUMMARY COMPARISON")
    print(f"{'='*60}")
    print(f"{'Image':<20} {'NRB Score':<15} {'Critical CVEs':<15} {'High CVEs'}")
    print(f"{'-'*60}")
    for r in all_results:
        print(f"{r['image']:<20} {str(r['compliance_score'])+'%':<15} {r['critical_cves']:<15} {r['high_cves']}")
    print(f"{'='*60}")
    print("\n[+] All scans complete. Open results/ folder to view reports.")
