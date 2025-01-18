import requests
import re
import base64
import os
from datetime import datetime
import logging
from urllib.parse import urlparse, parse_qs

class GitHubSASScanner:
    def __init__(self, github_token):
        self.github_token = github_token
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = "https://api.github.com"
        
        # SAS Token patterns
        self.sas_patterns = [
            # Pattern for SAS URL
            r'https?://[^/]+\.blob\.core\.windows\.net/[^?\s]+\?[^=\s]+=[^&\s]+&?(?:sig=|sv=|sp=)[^&\s]+',
            # Pattern for SAS Token
            r'(?:sig|sv|sp|st|se|sr)=[^&\s]+(?:&(?:sig|sv|sp|st|se|sr)=[^&\s]+)*'
        ]
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('sas_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def is_valid_sas_token(self, token):
        """Basic validation of SAS token structure"""
        required_params = ['sv', 'sig']  # Minimum required parameters
        try:
            # Check if it's a URL
            if token.startswith('http'):
                parsed = urlparse(token)
                params = parse_qs(parsed.query)
            else:
                params = parse_qs(token)
            
            return all(param in str(params) for param in required_params)
        except:
            return False

    def search_github(self, query, max_results=100):
        """Search GitHub repositories for potential SAS tokens"""
        findings = []
        page = 1
        
        while len(findings) < max_results:
            search_url = f"{self.base_url}/search/code"
            params = {
                'q': query,
                'per_page': 100,
                'page': page
            }
            
            try:
                response = requests.get(search_url, headers=self.headers, params=params)
                response.raise_for_status()
                results = response.json()
                
                if not results.get('items'):
                    break
                
                for item in results['items']:
                    repo_name = item['repository']['full_name']
                    file_path = item['path']
                    file_url = item['html_url']
                    
                    # Get file content
                    content = self.get_file_content(item['url'])
                    if content:
                        sas_tokens = self.extract_sas_tokens(content)
                        if sas_tokens:
                            for token in sas_tokens:
                                if self.is_valid_sas_token(token):
                                    finding = {
                                        'repository': repo_name,
                                        'file_path': file_path,
                                        'file_url': file_url,
                                        'token': token,
                                        'discovered_at': datetime.now().isoformat()
                                    }
                                    findings.append(finding)
                                    self.logger.warning(f"Found potential SAS token in {repo_name}/{file_path}")
                
                page += 1
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error searching GitHub: {str(e)}")
                break
                
            # Check for API rate limiting
            if response.headers.get('X-RateLimit-Remaining', '0') == '0':
                reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                self.logger.warning(f"GitHub API rate limit reached. Reset at {datetime.fromtimestamp(reset_time)}")
                break
        
        return findings

    def get_file_content(self, url):
        """Retrieve and decode file content"""
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            content = response.json().get('content', '')
            if content:
                return base64.b64decode(content).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Error getting file content: {str(e)}")
        return None

    def extract_sas_tokens(self, content):
        """Extract potential SAS tokens from content"""
        tokens = set()
        for pattern in self.sas_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                tokens.add(match.group())
        return tokens

    def scan_and_report(self, queries):
        """Main scanning function"""
        all_findings = []
        
        for query in queries:
            self.logger.info(f"Scanning for query: {query}")
            findings = self.search_github(query)
            all_findings.extend(findings)
        
        # Generate report
        self.generate_report(all_findings)
        return all_findings

    def generate_report(self, findings):
        """Generate a detailed report of findings"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f'sas_scan_report_{timestamp}.txt'
        
        with open(report_file, 'w') as f:
            f.write("Azure Storage SAS Token Exposure Report\n")
            f.write("=====================================\n\n")
            f.write(f"Scan Date: {datetime.now().isoformat()}\n")
            f.write(f"Total Findings: {len(findings)}\n\n")
            
            for i, finding in enumerate(findings, 1):
                f.write(f"Finding #{i}\n")
                f.write(f"Repository: {finding['repository']}\n")
                f.write(f"File: {finding['file_path']}\n")
                f.write(f"URL: {finding['file_url']}\n")
                f.write(f"Token: {finding['token']}\n")
                f.write(f"Discovered: {finding['discovered_at']}\n")
                f.write("-" * 50 + "\n")
        
        self.logger.info(f"Report generated: {report_file}") 