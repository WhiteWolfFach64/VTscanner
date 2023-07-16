# VTscanner
IOCs Management Tool

VTscanner is an IOC analysis tool, which is integrated with services such as VirusTotal via API for checking possible malicious elements and reporting. Currently the tool is integrated with APIs from AbuseIPDB and ViruTotal, but more services and functionalities would be added in the future.

For instalation, please follow these steps:
1. Clone the repository to your computer :      git clone https://github.com/WhiteWolfFach64/VTscanner.git
2. Update pip3 to lastest version :    pip3 install --upgrade pip
3. Run file "install.py" with sudo :   sudo python3 install.py
(This should create a directory for VTscanner tool in path "~/VTscanner" and install program in /usr/local/bin).
4. Run "VTscanner" by simply typying VTscanner (VTscanner can be called from any directory as long as "/usr/local/bin" belongs to "$PATH". If you encounter issues on running VTscanner, make sure "/usr/local/bin" is inside "$PATH" and add it if it is not):

In order to analyze any domain list, IP list, file or list of hashes, please, place them into "~/VTscanner/txt". This tool looks for elements to be analyzed in this directory.

When user run VTscanner for the first time will be promted to submit API keys for the services availables. Make sure to provide a valid API key, otherwise analysis will return errors. API keys will be saved into "~/VTscanner/APIs/API.txt", and user will be prompted for usage of already saved API keys in use or if he/she would prefer to submit different API keys.

No more talk! Let's hunt! 
                          🐺
