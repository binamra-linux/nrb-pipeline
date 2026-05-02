from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import sqlite3
import json
import threading
import sys
import os

# Add parent directory so we can import our pipeline modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nrb_mapper import map_to_nrb
from ai_advisor import advise_all_violations, generate_executive_report

app = Flask(__name__)
app.config["SECRET_KEY"] = "nrbshield-secret"
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")

# ── Database setup ─────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            image_name  TEXT NOT NULL,
            scan_time   TEXT NOT NULL,
            score       REAL,
            critical    INTEGER,
            high        INTEGER,
            medium      INTEGER,
            low         INTEGER,
            result_json TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_scan(report_data):
    nrb  = report_data["nrb_compliance"]
    cvec = report_data["cve_counts"]
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO scans
        (image_name, scan_time, score, critical, high, medium, low, result_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report_data["image"],
        report_data["scan_time"],
        nrb["compliance_score"],
        cvec.get("CRITICAL", 0),
        cvec.get("HIGH",     0),
        cvec.get("MEDIUM",   0),
        cvec.get("LOW",      0),
        json.dumps(report_data)
    ))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, image_name, scan_time, score, critical, high, medium, low "
        "FROM scans ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT result_json FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()
    return json.loads(row["result_json"]) if row else None

# ── Pipeline runner ────────────────────────────────────────────────

def run_pipeline_live(image_name, dockerfile_path, sid):
    """Run the full pipeline and emit progress to the browser via WebSocket."""
    import subprocess, re
    from datetime import datetime

    def log(msg):
        socketio.emit("log", {"msg": msg}, to=sid)

    def run_trivy(image):
        log("Running Trivy CVE scan...")
        safe = image.replace("/", "_").replace(":", "_")
        out  = f"/tmp/trivy_{safe}.json"
        subprocess.run(
            ["trivy", "image", "--format", "json",
             "--output", out, "--timeout", "5m", image],
            capture_output=True
        )
        try:
            with open(out) as f:
                return json.load(f)
        except:
            return {"Results": []}

    def run_hadolint(path):
        if not path:
            log("Skipping Hadolint (no Dockerfile for pulled image)")
            return []
        log("Running Hadolint Dockerfile linter...")
        r = subprocess.run(
            ["hadolint", "--format", "json", path],
            capture_output=True, text=True
        )
        try:
            return json.loads(r.stdout) if r.stdout.strip() else []
        except:
            return []

    def run_dockle(image):
        log("Running Dockle CIS benchmark...")
        r = subprocess.run(
            ["dockle", "--format", "json", "--no-registry", image],
            capture_output=True, text=True
        )
        output = (r.stdout + r.stderr).strip()
        match  = re.search(r"\{.*\}", output, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except:
                pass
        return {"details": [], "summary": []}

    def extract_cve_summary(trivy_data):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vulns  = []
        for result in trivy_data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                sev = v.get("Severity", "LOW")
                counts[sev] = counts.get(sev, 0) + 1
                vulns.append({
                    "id":            v.get("VulnerabilityID", ""),
                    "package":       v.get("PkgName", ""),
                    "severity":      sev,
                    "title":         v.get("Title", ""),
                    "fixed_version": v.get("FixedVersion", "Not available")
                })
        return counts, vulns

    try:
        log(f"Starting NRBShield scan for: {image_name}")
        socketio.emit("status", {"status": "running"}, to=sid)

        trivy_data    = run_trivy(image_name)
        hadolint_data = run_hadolint(dockerfile_path)
        dockle_data   = run_dockle(image_name)

        log("Mapping findings to NRB controls...")
        nrb_compliance           = map_to_nrb(trivy_data, hadolint_data, dockle_data)
        cve_counts, cve_list     = extract_cve_summary(trivy_data)

        report_data = {
            "image":          image_name,
            "scan_time":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cve_counts":     cve_counts,
            "cve_list":       cve_list[:20],
            "hadolint":       hadolint_data,
            "dockle":         dockle_data,
            "nrb_compliance": nrb_compliance,
            "ai_advisories":  [],
            "ai_narrative":   "",
        }

        log("Generating AI remediation advisories...")
        report_data["ai_advisories"] = advise_all_violations(nrb_compliance)

        log("Generating AI executive compliance narrative...")
        report_data["ai_narrative"]  = generate_executive_report(report_data)

        save_scan(report_data)
        log("Scan complete!")

        socketio.emit("result",  {"data": report_data}, to=sid)
        socketio.emit("status",  {"status": "done"},    to=sid)

    except Exception as e:
        log(f"Error: {str(e)}")
        socketio.emit("status", {"status": "error", "msg": str(e)}, to=sid)

# ── Routes ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    scans = get_all_scans()
    return render_template("index.html", scans=scans)

@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    data = get_scan_by_id(scan_id)
    if not data:
        return "Scan not found", 404
    return render_template("scan_detail.html", data=data)

@app.route("/compare")
def compare():
    id1  = request.args.get("id1", type=int)
    id2  = request.args.get("id2", type=int)
    scan1 = get_scan_by_id(id1) if id1 else None
    scan2 = get_scan_by_id(id2) if id2 else None
    scans = get_all_scans()
    return render_template("compare.html",
                           scan1=scan1, scan2=scan2, scans=scans,
                           id1=id1, id2=id2)

@app.route("/api/scans")
def api_scans():
    return jsonify(get_all_scans())

@socketio.on("start_scan")
def handle_scan(data):
    image      = data.get("image", "").strip()
    dockerfile = data.get("dockerfile", None) or None
    if not image:
        emit("log", {"msg": "Error: no image name provided"})
        return
    sid = request.sid
    thread = threading.Thread(
        target=run_pipeline_live,
        args=(image, dockerfile, sid),
        daemon=True
    )
    thread.start()

if __name__ == "__main__":
    init_db()
    print("\n  NRBShield Dashboard running at http://localhost:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
