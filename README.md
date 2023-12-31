# VTscanner
IOCs Management Tool

VTscanner is an IOC analysis tool, which is integrated with services such as VirusTotal via API for checking reputation of IOCs. Currently the tool is integrated with APIs from AbuseIPDB and ViruTotal, but more services and functionalities would be added in the future.

Current services available are:
1. IPs scanning tool (check for reputation of IPs)
2. File scanning tool (check for reputation on hashes and upload files to be scanned by VT's sandboxes)
3. Domains scanning tool (check for reputation of domains/URLs)

For instalation, please follow these steps:
1. Clone the repository to your computer :      git clone https://github.com/WhiteWolfFach64/VTscanner.git
2. Run file "install.py" with sudo :            python3 install.py
(This should create a directory for VTscanner tool in path "~/VTscanner", install program in /usr/local/bin, create a symbolic link for "VTscanner.py", upgrade pip3 to latest available version and install requirements).
3. Run "VTscanner" by simply typying VTscanner.py (VTscanner can be called from any directory as long as "/usr/local/bin" belongs to "$PATH". If you encounter issues on running VTscanner, make sure "/usr/local/bin" is added to "$PATH". Please, add it if it is not).

ATTENTION: Installing the tool with sudo privileges will end up in setting libraries and pip3 dependencies not only for local user but for all users in host. This is may a not desired behavior, so we recommend installing the tool from a directory where local user has executable permissions.

In order to analyze any domain list, IP list, file or list of hashes, please, place them into "~/VTscanner/txt". This tool looks for elements to be analyzed in this directory.

When user runs VTscanner for the first time will be prompted to submit API keys for the servies avaiable. Make sure to provide a valid API key, otherwise analysis will return errors. API keys will be saved into "~/VTscanner/APIs/API.txt". User will be prompted for usage of already saved API keys in use or rather change API key value for each of the services available.

No more talk! Let's hunt! 
                          🐺
