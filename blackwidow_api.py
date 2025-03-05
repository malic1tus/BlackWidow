import argparse
import json
from blackwidow import SecurityScanner

def run_scan_api(target, threads=5, timeout=10, depth=2):
    """Run scan and return results as JSON"""
    scanner = SecurityScanner(target, threads, timeout, depth)
    results = scanner.run_scan()
    
    # Convert results to JSON-serializable format
    api_results = {
        'target': results['target'],
        'timestamp': results['timestamp'],
        'ssl_check': [
            results['ssl_check'][0],
            str(results['ssl_check'][1]) if isinstance(results['ssl_check'][1], dict) else results['ssl_check'][1]
        ],
        'missing_headers': results['missing_headers'],
        'open_ports': results['open_ports'],
        'vulnerable_paths': results['vulnerable_paths'],
        'vulnerabilities': [
            {
                'type': vuln['type'],
                'param': vuln['param'],
                'url': vuln['url'],
                'payload': vuln['payload']
            } for vuln in scanner.vulns
        ]
    }
    
    return api_results

def main():
    parser = argparse.ArgumentParser(description='BlackWidow API')
    parser.add_argument('target', help='Target URL or IP')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('--depth', type=int, default=2, help='Maximum crawl depth')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    
    args = parser.parse_args()
    
    if args.json:
        results = run_scan_api(args.target, args.threads, args.timeout, args.depth)
        print(json.dumps(results, indent=2))
    else:
        scanner = SecurityScanner(args.target, args.threads, args.timeout, args.depth)
        scanner.run_scan()

if __name__ == "__main__":
    main()