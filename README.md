
## Clone The Repository:

   ```bash
  git clone https://github.com/rocksec00/JSRecon.git
  cd JSRecon
   ```

## Install requiered packages:

   ```bash
   pip3 install requirements.txt
   ```

## singlejs (For Single Domain)

To use the tool for a single domain:

1. Make the script executable:
   ```bash
   chmod +x singlejs
   ```

2. Move the script to `/usr/local/bin`:
   ```bash
   mv singlejs /usr/local/bin
   ```

3. Run the command for your domain:
   ```bash
   singlejs example.com
   ```

## multijs (For Subdomains)

To use the tool for subdomains:

1. Make the script executable:
   ```bash
   chmod +x multijs
   ```

2. Move the script to `/usr/local/bin`:
   ```bash
   mv multijs /usr/local/bin
   ```

3. If you don't have a list of subdomains, run:
   ```bash
   multijs -d example.com
   ```

4. If you have a list of subdomains in a text file (e.g., `subdomains.txt`), run:
   ```bash
   multijs -f subdomains.txt
   ```

## Note:
Once completed, the output file will be saved. Ex: results_20250204_224659.json
