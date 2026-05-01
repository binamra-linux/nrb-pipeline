from jinja2 import Environment, FileSystemLoader
import json
import os

def generate_report(data):
    """Generate HTML compliance dashboard from scan results."""
    env      = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html")
    output   = template.render(**data)
    
    safe_name = data["image"].replace(":", "_").replace("/", "_")
    path      = f"results/report_{safe_name}.html"
    
    with open(path, "w") as f:
        f.write(output)
    
    return path
