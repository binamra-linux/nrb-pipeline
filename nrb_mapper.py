import json

# Load NRB controls from the mapping file
with open("nrb_controls.json") as f:
    NRB_CONTROLS = json.load(f)["controls"]

def extract_flags(trivy_data, hadolint_data, dockle_data):
    """
    Extract boolean flags from all three tool outputs.
    Each flag represents one specific security issue being present or not.
    """

    # ── Trivy: collect all vulnerabilities ──────────────────────────
    all_vulns = []
    result_types = []
    for result in trivy_data.get("Results", []):
        result_types.append(result.get("Type", "").lower())
        for vuln in result.get("Vulnerabilities", []):
            all_vulns.append(vuln)

    severities  = [v.get("Severity", "") for v in all_vulns]
    pkg_names   = [v.get("PkgName",   "").lower() for v in all_vulns]
    crypto_pkgs = {"openssl", "libssl", "libgcrypt", "nss", "libnss3", "libcrypto"}
    os_types    = {"alpine", "debian", "ubuntu", "centos", "rhel", "amazon"}
    lib_types   = {"pip", "npm", "composer", "gem", "cargo", "gomod", "jar"}

    flags = {
        # Patch management (NRB-001)
        "trivy_critical_cves": "CRITICAL" in severities,
        "trivy_high_cves":     "HIGH" in severities,

        # Vulnerability assessment (NRB-002)
        "trivy_medium_cves":   "MEDIUM" in severities,
        "trivy_unfixed_cves":  any(
            v.get("FixedVersion", "") == "" for v in all_vulns
        ),

        # Secure communication (NRB-006)
        "trivy_openssl_cves":  any(p in pkg_names for p in ["openssl", "libssl"]),
        "trivy_libssl_cves":   "libssl" in pkg_names,

        # Cryptographic controls (NRB-008)
        "trivy_crypto_cves":   any(p in pkg_names for p in crypto_pkgs),

        # Technology risk - OS packages (NRB-010)
        "trivy_os_cves":       any(t in os_types for t in result_types),

        # Technology risk - app libraries (NRB-010)
        "trivy_library_cves":  any(t in lib_types for t in result_types),

        # Secret scanning (NRB-007)
        "trivy_secret_scan":   False,
    }

    # ── Hadolint: collect all rule codes ────────────────────────────
    hadolint_codes = {item.get("code", "") for item in hadolint_data}

    hadolint_flag_map = {
        "DL3002": "hadolint_DL3002",   # last USER should not be root
        "DL3006": "hadolint_DL3006",   # always tag base image
        "DL3007": "hadolint_DL3007",   # using latest tag
        "DL3008": "hadolint_DL3008",   # pin apt package versions
        "DL3009": "hadolint_DL3009",   # delete apt lists after install
        "DL3010": "hadolint_DL3010",   # use ADD for archives, not COPY
        "DL3011": "hadolint_DL3011",   # valid UNIX ports
        "DL3025": "hadolint_DL3025",   # use exec form of CMD
    }
    for code, flag in hadolint_flag_map.items():
        flags[flag] = code in hadolint_codes

    # ── Dockle: collect all CIS check codes ─────────────────────────
    dockle_details = dockle_data.get("details", [])
    dockle_codes   = {item.get("code", "") for item in dockle_details}

    dockle_flag_map = {
        "CIS-DI-0001": "dockle_CIS-DI-0001",   # do not run as root
        "CIS-DI-0005": "dockle_CIS-DI-0005",   # enable content trust
        "CIS-DI-0006": "dockle_CIS-DI-0006",   # add HEALTHCHECK
        "CIS-DI-0008": "dockle_CIS-DI-0008",   # remove setuid/setgid
        "CIS-DI-0009": "dockle_CIS-DI-0009",   # use COPY not ADD
        "CIS-DI-0010": "dockle_CIS-DI-0010",   # do not store secrets
        "CIS-DI-0011": "dockle_CIS-DI-0011",   # install verified packages
    }
    for code, flag in dockle_flag_map.items():
        flags[flag] = code in dockle_codes

    return flags


def map_to_nrb(trivy_data, hadolint_data, dockle_data):
    """
    Map all scan findings to NRB controls and calculate compliance score.
    Returns a dict with per-control results and an overall score.
    """
    flags = extract_flags(trivy_data, hadolint_data, dockle_data)

    compliance_results = []
    for control in NRB_CONTROLS:
        # Find which checks for this control actually triggered
        triggered = [
            check for check in control["mapped_checks"]
            if flags.get(check, False)
        ]
        compliant = len(triggered) == 0

        compliance_results.append({
            "id":               control["id"],
            "nrb_clause":       control["nrb_clause"],
            "nrb_document":     control["nrb_document"],
            "description":      control["nrb_description"],
            "compliant":        compliant,
            "violations":       triggered,
            "severity_weight":  control["severity_weight"],
            "remediation_hint": control["remediation_hint"],
        })

    # Calculate weighted compliance score
    total_weight  = sum(c["severity_weight"] for c in NRB_CONTROLS)
    failed_weight = sum(
        c["severity_weight"]
        for c in compliance_results
        if not c["compliant"]
    )
    score = round(((total_weight - failed_weight) / total_weight) * 100, 1)

    # Count CVEs for summary
    all_vulns = [
        vuln
        for result in trivy_data.get("Results", [])
        for vuln in result.get("Vulnerabilities", [])
    ]

    return {
        "controls":            compliance_results,
        "compliance_score":    score,
        "total_critical_cves": sum(1 for v in all_vulns if v.get("Severity") == "CRITICAL"),
        "total_high_cves":     sum(1 for v in all_vulns if v.get("Severity") == "HIGH"),
        "total_medium_cves":   sum(1 for v in all_vulns if v.get("Severity") == "MEDIUM"),
        "flags":               flags,
    }
