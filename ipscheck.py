#!/usr/bin/env python3

# Imports
import os
import sys
import re
import time
import requests
import ipaddress
import json

# Global Variables
API_KEY = sys.argv[1]
API_KEYAB = sys.argv[2]
API_URLVT = "https://www.virustotal.com/api/v3/ip_addresses/{}"
API_URLABUSE = "https://api.abuseipdb.com/api/v2/check"
headers = {
    "accept": "application/json",
    "x-apikey": API_KEY
}
RED = "\033[41m"
GREEN = "\033[42m"
BLACK = "\033[30m"
RESET = "\033[0m"
AQUA = '\033[96m'
REDON = '\033[91m'

# Functions
def intro():
    intro = AQUA + r"""
|-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-|

   _,_ ___  _,  _,  _, _, _ _, _ __, __,
   | /  |  (_  / ` /_\ |\ | |\ | |_  |_)
   |/   |  , ) \ , | | | \| | \| |   | \
   ~    ~   ~   ~  ~ ~ ~  ~ ~  ~ ~~~ ~ ~  

IPs Scanning Tool                      By WhiteWolf 🐺

|-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-|
""" + RESET
    print(intro)

def fin():
    banner()
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
    
def arrow():
    for dots in range(35):
        print("-", end='', flush= True)
        time.sleep(0.05)
    print(">   Done!")

def VTscanner(valid_ips):
    while True:
        print("Do you wish to proceed to scan IPs found? (Yes/No) ")
        DoScan = input(":")
        if DoScan.lower() in ("yes", "y"):
            print("Proceeding to scan", end="")
            dots()
            banner()
            malicious_ips = []  # Initialize an empty list to store malicious IPs
            for ip in valid_ips:
                banner()
                url = API_URLVT.format(ip)  # Update the URL to include the IP
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                    if malicious_count > 1:
                        print("IP " + AQUA + f"{ip} " + RESET + "is a " + RED + BLACK + "malicious IP!" + RESET + " Proceed to manual scan.")
                        malicious_ips.append(ip)  # Add the malicious IP to the list
                    else:
                        print("IP " + AQUA + f"{ip} " + RESET + "is " + GREEN + BLACK + "clean!" + RESET)
                else:
                    print("IP " + AQUA + f"{ip} " + RESET + "cannot be scanned.")
            banner()
            while True:
                print("\n" + "Do you wish to export malicious IPs into a list? (Yes/No)" + "\n")
                DoPutIntoList = input (":")
                if DoPutIntoList.lower() in ("yes", "y"):
                    if len(malicious_ips) > 0:
                        banner()
                        print("Exporting list", end="")
                        dots()
                        nl()
                        banner()
                        print("Here is the list of " + AQUA + f"{len(malicious_ips)}" + RESET + " malicious IPs:" + "\n")
                        for maliciousIP in malicious_ips:
                            print(REDON + maliciousIP + RESET)
                        nl()
                        print("Thanks for using this service! Have a nice day!")
                        banner()
                    else:
                        banner()
                        nl()
                        print("No malicious IPs were found! Have a nice day!")
                        banner()
                    break
                elif DoPutIntoList.lower() in ("no", "n"):
                    banner()
                    nl()
                    print("Alright! Exiting...")
                    banner()
                    time.sleep(3)
                    break
                    fin()
                    sys.exit(0)
                else:
                    banner()
                    nl()
                    print("Invalid input. Please, select a valid option")
                    nl()
                    banner()
            break
        elif DoScan.lower() in ("no", "n"):
            banner()
            nl()
            print("Alright! Exiting...")
            banner()
            break
            sys.exit(0)
        else:
            banner()
            nl()
            print("Invalid input. Please, select a valid option")
            nl()
            banner()
          
            
def ABUSEscanner(valid_ips):
    while True:
        print("Do you wish to proceed to scan IPs found? (Yes/No) ")
        DoScan = input(":")
        if DoScan.lower() in ("yes", "y"):
            url = API_URLABUSE
            headers = {
                'Accept': 'application/json',
                'Key': API_KEYAB
            }
            malicious_ips = []  # Initialize an empty list to store malicious IPs

            for ip in valid_ips:
                querystring = {'ipAddress': ip, 'maxAgeInDays': '120'}

                query = requests.get(url, headers=headers, params=querystring)
                response = query.json()
                banner()

                if 'data' in response:
                    if response['data']['abuseConfidenceScore'] >= 0:
                        if response['data']['abuseConfidenceScore'] >= 10:
                            print(AQUA + f"{ip}" + RESET + f" Confidence of Abuse = {response['data']['abuseConfidenceScore']} --> " + RED + BLACK + "Malicious IP!" + RESET)
                            print(f"Country Code: {response['data']['countryCode']}" + f" | Domain: {response['data']['domain']}")
                            print(f"ISP: {response['data']['isp']}" + f" | Is It TOR?: {response['data']['isTor']}")
                            malicious_ips.append(ip)
                        else:
                            print(AQUA + f"{ip}" + RESET + f": Confidence of Abuse = {response['data']['abuseConfidenceScore']} --> " + GREEN + BLACK + "IP is clean!" + RESET)
                            print(f"Country Code: {response['data']['countryCode']}" + f" | Domain: {response['data']['domain']}")
                            print(f"ISP: {response['data']['isp']}" + f" | Is It TOR?: {response['data']['isTor']}")
                    else:
                        print(AQUA + f"IP {ip}" + RESET + " cannot be scanned")
                else:
                    print(f"No data available for IP {ip}")
                    #print(response)

            break  # Move the break statement here
        elif DoScan.lower() in ("no", "n"):
            nl()
            banner()
            print("Alright! Exiting...")
            banner()
            time.sleep(1)
            fin()
            sys.exit(0)
        else:
            banner()
            nl()
            print("Invalid input. Please, select a valid option.")
            nl()
            banner()


    nl()
    while True:
        print("\n" + "Do you wish to export malicious IPs into a list? (Yes/No)" + "\n")
        DoPutIntoList = input (":")
        if DoPutIntoList.lower() in ("yes", "y"):
            if len(malicious_ips) > 0:
                banner()
                print("Exporting IPs", end="")
                dots()
                nl()
                print("Here is the list of " + AQUA + f"{len(malicious_ips)}" + RESET + " malicious IPs:" + "\n")
                for maliciousIP in malicious_ips:
                    print(REDON + maliciousIP + RESET)
                nl()
                print("Thanks for using this service! Have a nice day!")
                banner()
            else:
                banner()
                nl()
                print("No malicious IPs were found! Have a nice day!")
                banner()
            break
        elif DoPutIntoList.lower() in ("no", "n"):
            nl()
            banner()
            print("Alright! Exiting...")
            banner()
            time.sleep(1)
            break
            fin()
            sys.exit(0)
        else:
            banner()
            nl()
            print("Invalid input. Exiting... ")
            nl()
            banner()


		
# -- CODE EXECUTION  --  #

intro()
banner()
chooseFile = input("Choose a file: ")
banner()

filePath = os.path.expanduser(f"~/VTscanner/txt/{chooseFile}")

if os.path.exists(filePath):
    foundFile = filePath
    print("File found:", foundFile)
    banner()
    print("Proceeding to scan file in search for IPs")
    dots()
    banner()
else:
    print("File not found. Exiting...")
    banner()
    time.sleep(3)
    fin()
    sys.exit(1)

# Identifying IPs, saving them into a variable, and printing them
with open(foundFile, "r") as file:
    content = file.read()
    ip_list = re.findall(r"(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[A-Fa-f0-9:]{2,39}(?:%[A-Za-z0-9]{1,})?)", content)

    valid_ips = set()  # Use a set to store unique IP addresses
    for ip in ip_list:
        if ':' in ip:
            # IPv6 address
            if ip.startswith('::') or ip.endswith('::') or '::' in ip or ip.startswith(':') or ip.endswith(':') or ':' in ip:
                valid_ips.add(ip)  # Use add() method for sets
        else:
            # IPv4 address
            octets = ip.split('.')
            if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                valid_ips.add(ip)  # Use add() method for sets

    # Print the valid IPs
    print("File read! " + AQUA + f"{len(valid_ips)} " + RESET + "unique IPs have been found:\n")
    if len(valid_ips) > 0:
        pass
    else:
        print("No IPs have been found. Have a nice day!")
        banner()
        fin()
        sys.exit(0)
    for ip in valid_ips:
        print(AQUA + ip + RESET)


# Choosing Service and executing the corresponding function
banner()
while True:
    print(r"""Which service would you like to use for scanning IPs found? (Select the number of the desired service)
1 ---------------> VT
2 ---------------> AbuseIPDB
""")

    choosePlatform = input(":")
    if choosePlatform == "1":
        print("Redirecting to VT", end="")
        arrow()
        banner()
        print(AQUA + "Service selected was VT" + RESET)
        banner()
        VTscanner(valid_ips)
        break
    elif choosePlatform == "2":
        print("Redirecting to AbuseIPDB", end="")
        arrow()
        banner()
        print(AQUA + "Service selected was AbuseIPDB" + RESET)
        banner()
        ABUSEscanner(valid_ips)
        break
    else:
        banner()
        print("No valid service was selected. Please, select a valid service.")
        time.sleep(1)
        banner()

    

time.sleep(3)
fin()
