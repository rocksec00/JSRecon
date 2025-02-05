## JSRecon - JavaScript Secrets Reconnaissance Tool

JsRecon is a powerful and automated tool designed to extract and identify secrets hidden within JavaScript (.js) files. It is particularly useful for discovering hardcoded credentials, API keys, and URLs that may pose security risks. By scanning and analyzing JavaScript files hosted on a target domain, JsRecon helps security researchers and penetration testers efficiently uncover potential vulnerabilities.

## How JSRecon Tool Works

JsRecon operates using a structured flow to find secrets and URLs in JavaScript (.js) files. It provides two scanning options:

1. Single Domain Scan
2. Subdomain Scan

Before running the tool, ensure you have it installed properly. Follow the installation steps provided in the tool’s documentation or repository.

Running the Tool

**1. Single Domain Scan**

The tool crawls all URLs associated with the specified domain.
It filters out JavaScript (.js) files from the collected URLs.
JsRecon scans these .js files to extract secrets (API keys, credentials, etc.) and additional URLs present in them.

**2. Subdomain Scan**

The tool first enumerates all subdomains of the target domain.
It fetches URLs from these subdomains.
Similar to the single domain scan, it filters out JavaScript (.js) files from the collected URLs.
Finally, it scans these .js files to find secrets and extract any additional URLs.

By following this process, JsRecon helps identify hardcoded secrets efficiently across both single domains and their subdomains.

## Key Features:

Scans JavaScript files to detect hardcoded secrets, API keys, and URLs.

**Supports multiple scanning options:**

**Single Domain Scan** – Crawls and analyzes JavaScript files from a single domain.

**Subdomain Scan** – Enumerates subdomains and scans their JavaScript files.

**Subdomain List Scan** – Accepts a list of subdomains from a text file and performs scans.

**Single JavaScript URL Scan** – Scans a specific JavaScript file for secrets.

**Multiple JavaScript File Scan** – Accepts a list of .js files from a text file and analyzes them.

By automating the reconnaissance process, JsRecon simplifies JavaScript security analysis, making it an essential tool for ethical hackers and security professionals.

## Installation Steps

 **Required Tools:**

   ```bash
 go install github.com/projectdiscovery/katana/cmd/katana@latest
 go install github.com/tomnomnom/assetfinder@latest
   ```
If Not Access the go tool ; run
  ```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
   ```

**Clone The Repository:**

   ```bash
  git clone https://github.com/rocksec00/JSRecon.git
  cd JSRecon
   ```
**Install requiered packages:**

   ```bash
   pip3 install -r requirements.txt
   ```

**singlejs (For Single Domain)**

To use the tool for a single domain:

1. Make the script executable:
   ```bash
   chmod +x singlejs
   ```
   
2. If you want to Run Globally Move or Copy the script to `/usr/local/bin`:
   
   For Move
   
   ```bash
   mv singlejs /usr/local/bin
   ```
   For Copy
   
      ```bash
   cp singlejs /usr/local/bin
   ```
   
3. Help
   ```bash
   singlejs -h

4. Run the following command for your domain: **(If you use globally access ignore "python3")**
   ```bash
   python3 singlejs example.com
   ```
5. Run the command following for single JS Url: **(If you use globally access ignore "python3")**
   ```bash
   python3 singlejs --js-url  https://example.com/congif.js
   ```
6. If you have a list of JS Urls in a text file (e.g., js.txt), run: **(If you use globally access ignore "python3")**
   ```bash
   python3 singlejs --js-file  js.txt
   ```

**multijs (For Subdomains)**

To use the tool for subdomains:

1. Make the script executable:
   ```bash
   chmod +x multijs
   ```

2. If you want to Run Globally Move or Copy the script to `/usr/local/bin`:
   
   For Move
   
   ```bash
   mv multijs /usr/local/bin
   ```
   For Copy
   
      ```bash
   cp multijs /usr/local/bin
   ```
3. Help
   
   ```bash
   multijs -h
   ```
   
4. If you don't have a list of subdomains, run: **(If you use globally access ignore "python3")**
   ```bash
   python3 multijs -d example.com --threads 20
   ```

5. If you have a list of subdomains in a text file (e.g., `subdomains.txt`), run: **(If you use globally access ignore "python3")**
   ```bash
   python3 multijs -f subdomains.txt --threads 20
   ```

## Note:
Once completed, the output file will be saved. Ex: results_20250204_224659.json
