# Imports
import os
import sys
import re
import time
import requests

# Global Variables
API_KEY = sys.argv[1]
API_URL = 'https://www.virustotal.com/api/v3/domains/{domain}'
RED = "\033[41m"
GREEN = "\033[42m"
BLACK = "\033[30m"
RESET = "\033[0m"
AQUA = '\033[96m'
REDON = '\033[91m' 

# Functions
def intro():
    intro = AQUA + r"""
|-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-|
   
   _,_ ___  _,  _,  _, _, _ _, _ __, __,
   | /  |  (_  / ` /_\ |\ | |\ | |_  |_)
   |/   |  , ) \ , | | | \| | \| |   | \
   ~    ~   ~   ~  ~ ~ ~  ~ ~  ~ ~~~ ~ ~  
   
Domains Scanning Tool		           By WhiteWolf 🐺

|-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-|
""" + RESET
    print(intro)

def fin():
    print(AQUA + "FIN" + RESET)

def nl():
    print("\n")

def banner():
    print("-" * 50)

def dots():
    for dots in range(3):
        print(".", end='', flush=True)
        time.sleep(1)
    print()


def VTScanning():
    while True:
        Scan = input("Would you like to proceed with scanning? (Yes/No): ")
        
        if Scan in ["Yes", "yes", "Y", "y"]:
            print("Proceeding to scan", end='')
            dots()
            banner()
            break
        elif Scan in ["No", "no", "N", "n"]:
            print("Alright! Exiting...")
            banner()
            time.sleep(1)
            banner()
            fin()
            sys.exit(0)
        else:
            banner()
            nl()
            print("Invalid input. Please, select a valid option.")
            nl()
            banner()
       

def scanDomains(domains):
    results = []
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    for domain in domains:
        url = API_URL.format(domain=domain)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print("Scanning domain " + AQUA + f"{domain} " + RESET, end='')
            data = response.json()
            if "data" in data:  # Check if "data" key exists in the response
                result = data["data"].get("attributes", {}).get("last_analysis_stats", {}).get("malicious")
                if result is None:
                    print("Cannot determine the scan result. Proceed to manual scan!")
                elif result > 0:
                    print(RED + BLACK + "Malicious Domain." + RESET + "\n" + RED + BLACK + "Proceed to manual scan!" + RESET)
                    results.append(domain)  # Add the malicious domain to the results list
                    banner()
                else:
                    print(GREEN + BLACK + "Domain is clean!" + RESET)
                    banner()
            else:
                print(f"Domain {domain} cannot be scanned")
                banner()
        else:
            print(f"Domain {domain} cannot be scanned")
            banner()

    nl()
    while True:
        doExport = input("Would you like to export malicious domains to a list? (Yes/No): ")
        banner()
        nl()

        if doExport.lower() in ["yes", "y"]:
            if len(results) > 0:
                print(f"This is the list of " + AQUA + f"{len(results)} " + RESET + "malicious domains:\n")
                for domain in results:
                    print(REDON + domain + RESET)  # Print all the malicious domains
                print("\n" + "Thanks for using this service! Have a nice day!")
                time.sleep(1)
                banner()
            else:
                nl()
                print("No malicious domains found. Have a nice day!")
                banner()
                time.sleep(1)
            break
        elif doExport.lower() in ["no", "n"]:
            print("Alright! Exiting...")
            time.sleep(1)
            banner()
            break
        else:
            print("Invalid input. Please, select a valid option.")
            nl()
            banner()

# Code Execution
intro()
banner()
chooseFile = input("Choose a file: ")
banner()
filePath = os.path.expanduser(f"~/VTscanner/txt/{chooseFile}")  # Update the file path
if os.path.exists(filePath):
    foundFile = filePath
    print("File found:", foundFile)
    banner()
else:
    print("File not found. Exiting...")
    banner()
    time.sleep(3)
    banner()
    fin()
    sys.exit(1)

time.sleep(3)
print("Reading " + chooseFile, end='')
dots()
nl()
banner()
with open(foundFile, "r") as file:
    # Combine the two patterns using the OR operator (|)
    pattern = r"(?i)\b([a-z0-9-]+(?:\.[a-z0-9-]+)+|[a-z0-9-]+(?:-?[a-z0-9-]+)*\.[a-z0-9-]+(?:-?[a-z0-9-]+)*\.[a-z0-9-]+)\b"

    content = file.read()
    domains = re.findall(pattern, content)
    domains = list(set(domains))  # Remove duplicates by converting to a set and then back to a list

    print(f"File read! Here are your " + AQUA + f"{len(domains)} " + RESET +  "unique domains:\n")
    for domain in domains:
        print(AQUA + domain + RESET)

    if len(domains) > 0:
        pass
    else:
        print("No domains were found. Have a nice day!")
        banner()
        fin()
        sys.exit(0)


time.sleep(2)
nl()
banner()
VTScanning()
scanDomains(domains)
banner()
fin()
