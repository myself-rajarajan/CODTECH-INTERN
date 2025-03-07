import requests
from bs4 import BeautifulSoup
import datetime

class WebVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.forms = []
        self.log_file = "scan_results.txt"

    def log(self, message):
        """Logs messages to both console and file."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        
        print(log_message)
        with open(self.log_file, "a") as file:
            file.write(log_message + "\n")

    def check_url(self):
        """Checks if the URL is reachable."""
        try:
            response = self.session.get(self.target_url, timeout=5)
            if response.status_code == 200:
                self.log(f"[+] Successfully connected to {self.target_url}")
                return True
            else:
                self.log(f"[!] Warning: Received HTTP {response.status_code} from {self.target_url}")
                return False
        except requests.exceptions.RequestException as e:
            self.log(f"[!] Error: Unable to reach {self.target_url} ({e})")
            return False

    def get_forms(self):
        """Extracts forms from the target web page."""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, "html.parser")
            self.forms = soup.find_all("form")
            self.log(f"[+] Found {len(self.forms)} forms on the page.")
        except Exception as e:
            self.log(f"[!] Error while parsing forms: {e}")

    def test_xss(self):
        """Tests forms for Cross-Site Scripting (XSS) vulnerabilities."""
        xss_payload = "<script>alert('XSS')</script>"
        for form in self.forms:
            action = form.attrs.get("action")
            method = form.attrs.get("method", "get").lower()
            inputs = form.find_all("input")
            data = {}

            for input_tag in inputs:
                name = input_tag.attrs.get("name")
                if name:
                    data[name] = xss_payload

            target = self.target_url + action if action else self.target_url

            try:
                if method == "post":
                    response = self.session.post(target, data=data)
                else:
                    response = self.session.get(target, params=data)

                if xss_payload in response.text:
                    self.log(f"[!] XSS vulnerability detected in {target}")
                else:
                    self.log(f"[+] No XSS detected in {target}")
            except Exception as e:
                self.log(f"[!] Error testing XSS in {target}: {e}")

    def test_sql_injection(self):
        """Tests for SQL Injection vulnerabilities."""
        sql_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users --"]
        for payload in sql_payloads:
            target = f"{self.target_url}?id={payload}"

            try:
                response = self.session.get(target)

                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    self.log(f"[!] Possible SQL Injection detected at {target}")
                else:
                    self.log(f"[+] No SQL Injection detected at {target}")
            except Exception as e:
                self.log(f"[!] Error testing SQL Injection in {target}: {e}")

    def test_insecure_headers(self):
        """Checks for missing security headers."""
        try:
            response = self.session.get(self.target_url)
            security_headers = [
                "X-Frame-Options",
                "Content-Security-Policy",
                "X-XSS-Protection",
                "X-Content-Type-Options"
            ]
            
            for header in security_headers:
                if header not in response.headers:
                    self.log(f"[!] Missing security header: {header}")
        except Exception as e:
            self.log(f"[!] Error checking security headers: {e}")

    def run(self):
        """Runs all tests and logs results."""
        self.log(f"\n===== Starting Scan: {self.target_url} =====")
        
        if not self.check_url():
            self.log("[!] Scan aborted due to connection issues.")
            return
        
        self.get_forms()
        self.test_xss()
        self.test_sql_injection()
        self.test_insecure_headers()
        
        self.log("===== Scan Complete! Results saved to scan_results.txt =====\n")

# Usage
if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://example.com): ").strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        print("[!] Invalid URL. Please include 'http://' or 'https://'")
    else:
        scanner = WebVulnerabilityScanner(target)
        scanner.run()
        print(f"\n[+] Results saved to scan_results.txt")
