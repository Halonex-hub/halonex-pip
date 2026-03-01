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
    print("Starting Security Scan...")
    
    # The init() function returns the scanning thread
    thread = init(api_key=args.api_key, generate_report=not args.no_report)
    
    if thread:
        # Wait for the background thread to finish
        thread.join()
        
    print("\nScan complete. Exiting.")

if __name__ == "__main__":
    main()
