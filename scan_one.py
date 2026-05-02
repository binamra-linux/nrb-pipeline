import sys
from pipeline import run_pipeline

# Usage: python3 scan_one.py <image-name> [dockerfile-path]
image      = sys.argv[1]
dockerfile = sys.argv[2] if len(sys.argv) > 2 else None
run_pipeline(image, dockerfile)
