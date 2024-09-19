import requests
import json
from bs4 import BeautifulSoup as BS
from concurrent.futures import ThreadPoolExecutor, as_completed 
import sys

def read_subdomains(file):
    with open(file) as f:
        return f.read().splitlines()

def check_subdomain(subdomain, domain, outfile, subdomains_results):
    try:
        url = f"http://{subdomain}" + '.' + domain
        hdict = {"User-agent": "Googlebot"}
        resp = requests.get(url, headers=hdict)
        scode = resp.status_code
        redirect = resp.headers.get('Location', None) if scode in [301, 302] else None

        output_line = f"{url} {scode} {redirect if redirect else ''}"
        print(f"[+] Discovered: {output_line}")
        
        outfile.write(output_line + "\n")
        subdomains_results.write(f"{subdomain}.{domain}\n")

    except requests.ConnectionError:
        print(f"[!] Connection error for {url}")

def virus_total_query(domain, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey': api_key, 'domain': domain}
    try:
        response = requests.get(url, params=params)
        jdata = response.json()
        subdomains = sorted(jdata.get('subdomains', []))

        with open("virus_total_subdomains.txt", 'w') as f:
            for sub in subdomains:
                f.write(f"{sub}\n")
                print(f"[+] Found subdomain from VirusTotal: {sub}")
                
        return subdomains

    except KeyError:
        print(f"No domains found for {domain}")
        return []
    except requests.ConnectionError:
        print("Could not connect to VirusTotal", file=sys.stderr)
        return []

def archive_urls(host):
    url = f"http://web.archive.org/cdx/search/cdx?url={host}*&output=txt"
    try:
        response = requests.get(url)
        archived_urls = response.text.splitlines()

        with open("archived_urls.txt", 'w') as f:
            for url in archived_urls:
                f.write(f"{url}\n")
                print(f"[+] Archived URL: {url}")
                
        return archived_urls
    except requests.ConnectionError:
        print(f"[!] Connection error for {host}")
        return []

def probe_directory(subdomain, directory, hdict):
    url = f"http://{subdomain}{directory}"
    try:
        resp = requests.get(url, headers=hdict, allow_redirects=False)  
        scode = resp.status_code
        
        # Handle all 30x redirection codes
        if 300 <= scode < 400:
            redirect_location = resp.headers.get('Location', 'Unknown')
            return (url, scode, redirect_location)
        elif scode not in [404, 400, 403]:
            return (url, scode, resp.url)
        else:
            return None
    except requests.ConnectionError:
        return None

def directory_probing(subdomains, directory, max_workers=10):
    discovered_dirs = []
    hdict = {"User-agent": "Googlebot"}

    print(f"\n[!] Probing directory '{directory}' across all subdomains...\n")
    
    try:
        with open("discovered_directories.txt", 'w') as f:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(probe_directory, subdomain, directory, hdict): subdomain for subdomain in subdomains}

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        url, code, *redirect_info = result
                        if code >= 300 and code < 400:  
                            redirect_url = redirect_info[0]
                            output_line = f"{url} {code} Redirected to: {redirect_url}"
                        else:
                            output_line = f"{url} {code}"

                        f.write(output_line + "\n")
                        print(f"[+] Discovered Directory: {output_line}")
                        
                        discovered_dirs.append(result)

    except Exception as e:
        print(f"[!] An error occurred during probing: {e}")
    
    return discovered_dirs

def main():
    print(r'''
    ______                       _____           _ _    _ _   
    | ___ \                     |_   _|         | | |  (_) |  
    | |_/ /___  ___ ___  _ __     | | ___   ___ | | | ___| |_ 
    |    // _ \/ __/ _ \| '_ \    | |/ _ \ / _ \| | |/ / | __|
    | |\ \  __/ (_| (_) | | | |   | | (_) | (_) | |   <| | |_ 
    \_| \_\___|\___\___/|_| |_|   \_/\___/ \___/|_|_|\_\_|\__|
                                                                                                                      
    ''')
    choice = input("Choose an option: \n\n1) Subdomain Discovery \n2) VirusTotal \n3) Archive URLs \n4) Directory Probing\n\n>")

    if choice == '1':
        try:
            file = input("Enter the subdomains file name (e.g., subs.txt): ") #subs.txt attached file
            domain = input("Enter the target domain (e.g., example.com): ") 
            subdomains = read_subdomains(file)

            with open("discovered_subdomains.txt", 'a') as outfile, open("subdomains_results.txt",'a') as results :
                print("\n[!] Press Ctrl+C to stop the discovery at any time...\n")
            
                for sub in subdomains:
                    check_subdomain(sub, domain, outfile, results)

        except KeyboardInterrupt:
            print("\n[!] Discovery stopped by user.")
        finally:
            print("[*] Output file has been saved and closed.")
        
    elif choice == '2':
        domain = input("Enter a domain for VirusTotal lookup (e.g., example.com): ")
        api_key = input("Enter your VirusTotal API key: ")
        virus_total_query(domain, api_key)

    elif choice == '3':
        host = input("Enter the host (e.g., example.com): ")
        archive_urls(host)

    elif choice == '4':
        file = input("Enter the subdomains file name (e.g., subs.txt): ") 
        directory = input("Enter the directory to probe (e.g., /admin/): ")
        subdomains = read_subdomains(file)
        directory_probing(subdomains, directory)

if __name__ == "__main__":
    main()

