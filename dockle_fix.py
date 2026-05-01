import subprocess
import json
import re

def run_dockle(image_name):
    """Run Dockle with robust output parsing."""
    print(f"  [*] Running Dockle CIS checks on {image_name}...")
    result = subprocess.run(
        ["dockle", "--format", "json", image_name],
        capture_output=True, text=True
    )
    
    # Combine stdout and stderr
    output = (result.stdout + result.stderr).strip()
    
    # Try to extract JSON object from output
    # Dockle sometimes prints log lines before the JSON
    json_match = re.search(r'\{.*\}', output, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except:
            pass
    
    # If no JSON found return empty structure
    print(f"  [!] Dockle returned no parseable JSON for {image_name}")
    return {"details": [], "summary": []}
