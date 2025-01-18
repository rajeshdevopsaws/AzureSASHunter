from github_sas_scanner import GitHubSASScanner
import os
import sys

def main():
    github_token = os.getenv('GITHUB_TOKEN')
    if not github_token:
        print("Please set GITHUB_TOKEN environment variable")
        sys.exit(1)

    # Initialize scanner
    scanner = GitHubSASScanner(github_token)

    # Define search queries
    queries = [
        'blob.core.windows.net sig=',
        'sv= sp= sig= blob.core.windows.net'
    ]

    # queries = [
    #     'blob.core.windows.net sig=',
    #     'sv= sp= sig= blob.core.windows.net',
    #     'SharedAccessSignature sr=',
    #     'filename:config* blob.core.windows.net',
    #     'filename:.env blob.core.windows.net',
    #     'filename:settings* blob.core.windows.net'
    # ]

    # Run scan
    findings = scanner.scan_and_report(queries)
    
    print(f"\nScan complete. Found {len(findings)} potential SAS token exposures.")
    print("Please check the generated report for details.")

if __name__ == "__main__":
    main() 