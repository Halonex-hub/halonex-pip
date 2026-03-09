import argparse
import sys
import os
import threading
from . import init
from .config import Config
from .sensor import Sensor
from .telemetry import Telemetry

def main():
    parser = argparse.ArgumentParser(description="Package Guardian - Security Scanner")
    
    parser.add_argument("--api-key", help="Your API Key")
    parser.add_argument("--no-report", action="store_true", help="Disable HTML report generation")
    
    args = parser.parse_args()
    
    # Run scan
    thread = init(api_key=args.api_key, generate_report=not args.no_report)
    
    if thread:
        thread.join()
        
    print("Scan complete. View your dashboard at: http://localhost:8000")

if __name__ == "__main__":
    main()
