## Required Tools:

   ```bash
 go install github.com/projectdiscovery/katana/cmd/katana@latest
 go install github.com/tomnomnom/assetfinder@latest
   ```
If Not Access the go tool ; run
  ```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
   ```

## Clone The Repository:

   ```bash
  git clone https://github.com/rocksec00/JSRecon.git
  cd JSRecon
   ```
## Install requiered packages:

   ```bash
   pip3 install -r requirements.txt
   ```

## singlejs (For Single Domain)

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

4. Run the command for your domain:
   ```bash
   singlejs example.com
   ```
5. Run the command for single JS Url:
   ```bash
   singlejs --js-url  https://example.com/congif.js
   ```
6. If you have a list of JS Urls in a text file (e.g., js.txt), run:
   ```bash
   singlejs --js-file  js.txt
   ```

## multijs (For Subdomains)

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
   
4. If you don't have a list of subdomains, run:
   ```bash
   multijs -d example.com --threads 20
   ```

5. If you have a list of subdomains in a text file (e.g., `subdomains.txt`), run:
   ```bash
   multijs -f subdomains.txt --threads 20
   ```

## Note:
Once completed, the output file will be saved. Ex: results_20250204_224659.json
