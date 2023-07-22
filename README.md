# VTscanner
IOCs Management Tool

VTscanner is an IOC analysis tool, which is integrated with services such as VirusTotal via API for checking possible malicious elements and reporting. Currently the tool is integrated with APIs from AbuseIPDB and ViruTotal, but more services and functionalities would be added in the future.

Current services available are:
1. IPs scanning tool (check for reputation of IPs)
2. File scanning tool (check for reputation on hashes and upload files to be scanned by VT's sandboxes)
3. Domains scanning tool (check for reputation of domains/URLs)

For instalation, please follow these steps:
1. Clone the repository to your computer :      git clone https://github.com/WhiteWolfFach64/VTscanner.git
2. Update pip3 to lastest version :    pip3 install --upgrade pip
3. Run file "install.py" with sudo :   sudo python3 install.py
(This should create a directory for VTscanner tool in path "~/VTscanner" and install program in /usr/local/bin).
4. Run "VTscanner" by simply typying VTscanner.py (VTscanner can be called from any directory as long as "/usr/local/bin" belongs to "$PATH". If you encounter issues on running VTscanner, make sure "/usr/local/bin" is added to "$PATH". Please, add it if it is not):

In order to analyze any domain list, IP list, file or list of hashes, please, place them into "~/VTscanner/txt". This tool looks for elements to be analyzed in this directory.

When user runs VTscanner for the first time will be prompted to submit API keys for the servies avaiable. Make sure to provide a valid API key, otherwise analysis will return errors. API keys will be saved into "~/VTscanner/APIs/API.txt". User will be prompted for usage of already saved API keys in use or rather change API key value for each of the services available.

No more talk! Let's hunt! 
                          🐺
