## Disclaimer: 
> This script is intended solely for ethical hacking and bug bounty hunting purposes. Please ensure you have explicit authorization before running this tool on any domain or system. Unauthorized use may violate laws or regulations.

## Description: 
Reconsub is a python-based toolkit enables security researchers and bug hunters to perform several reconnaissance tasks including subdomain brute-forcing, querying VirusTotal for associated subdomains, retrieving archived URLs, and probing directories on discovered subdomains. It's designed for efficient multi-threaded execution to deliver results rapidly and outputs them to files for further analysis.

## Features

- **Subdomain Discovery**: Brute-force subdomains using a provided list and checks the status codes.
- **VirusTotal Query**: Fetches associated subdomains from VirusTotal's API for a target domain.
- **Archive URL Retrieval**: Retrieves historical URLs stored in the Wayback Machine for a target domain.
- **Directory Probing**: Probes directories on discovered subdomains, identifying valid or redirected paths.


## How To Use:
**Clone the repository:**
```
git clone https://github.com/mnm-an/reconsub.git
cd reconsub
```
**Install dependencies:**
```
pip install -r requirements.txt
```
**Run the tool:**
```
python recontoolkit.py
```

## Functionality Overview:

### 1. Subdomain Discovery

**Description**: This module reads subdomains from a file (e.g., `subs.txt`) and checks their availability by appending them to the target domain.

**Input Guide**:
- **Subdomains file**: A text file with subdomains listed line by line (e.g., `subs.txt`).
- **Domain**: The domain to append subdomains to (e.g., `example.com`).
- The results will be saved in `discovered_subdomains.txt` and printed to the console.

### 2. VirusTotal Query

**Description**: Fetches subdomains related to the target domain using the VirusTotal API.

**Input Guide**:
- **Domain**: The domain to look up (e.g., `subs.txt`).
- **VirusTotal API Key**: A valid VirusTotal API key (required for authentication).
- The results will be saved in `virus_total_subdomains.txt`.


### 3. Archive URLs Retrieval

**Description**: Retrieves archived URLs from the Wayback Machine for the specified domain.

**Input Guide**:
- **Domain**: The domain to query (e.g., `subs.txt`).
- The results will be saved in `archived_urls.txt`.


### 4. Directory Probing

**Description**: Probes specific directories across all discovered subdomains for valid or redirected paths.

**Input Guide**:
- **Subdomains file**: A file containing the subdomains (e.g., `subdomains_alive.txt`).
- **Directory**: The directory to probe (e.g., `/admin/`, `/login`).
- The results will be saved in `discovered_directories.txt`.



## Contribution and Legal Disclaimer

>This tool is for authorized and legal use only, such as bug bounty programs or assessments where explicit permission has been granted. Contributions are welcome to improve functionality or fix bugs. Please submit issues or pull requests through the GitHub repository.

## License

MIT
