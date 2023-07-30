#!/usr/bin/env python3

# Imports
import os
import sys
import re
import time
import requests
import ipaddress
import json
import subprocess
import sniff

#Global Variables
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

IOCs Scan Management Tool                      By WhiteWolf 🐺

           🩸        LET'S HUNT              🩸

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
    
# ------------- CODE EXECUTION ------------------------------
intro()

API_FILE_PATH = os.path.expanduser("~/VTscanner/APIs/API.txt")

def read_api_keys():
    if not os.path.isfile(API_FILE_PATH):
        return "", ""

    with open(API_FILE_PATH, "r") as file:
        api_data = json.load(file)
        api_key = api_data.get("API_KEY", "")
        api_keyab = api_data.get("API_KEYAB", "")

    return api_key, api_keyab

def write_api_keys(api_key, api_keyab):
    api_data = {
        "API_KEY": api_key,
        "API_KEYAB": api_keyab
    }

    os.makedirs(os.path.dirname(API_FILE_PATH), exist_ok=True)

    with open(API_FILE_PATH, "w") as file:
        json.dump(api_data, file)

def check_api_keys():
    api_key, api_keyab = read_api_keys()

    if not api_key:
        banner()
        api_key = input("Please enter a value for VT API key: ")
        banner()
        print("API key value set for VT to: " + AQUA + f"{api_key}" + RESET)
        banner()
    else:
        banner()
        api_key_set = input("API value already set for VT. Would you like to change the API value? (Yes/No)")
        if api_key_set.lower() in ('yes', 'y'):
            banner()
            api_key = input("Please enter a value for VT API key: ")
            banner()
            print("API key value set for VT to: " + AQUA + f"{api_key}" + RESET)
            banner()
        elif api_key_set.lower() in ('no', 'n'):
            nl()
            print("Keeping the current value of the VT API key")
        else:
            nl()
            print("Invalid input. Keeping the current value of the VT API key")

    nl()

    if not api_keyab:
        banner()
        api_keyab = input("Please enter a value for AbuseIPDB API key: ")
        banner()
        print("API key value set for AbuseIPDB to: " + AQUA + f"{api_keyab}" + RESET)
    else:
        banner()
        api_keyab_set = input("API value already set for AbuseIPDB. Would you like to change the API value? (Yes/No)")
        if api_keyab_set.lower() in ('yes', 'y'):
            banner()
            api_keyab = input("Please enter a value for AbuseIPDB API key: ")
            banner()
            print("API key value set for AbuseIPDB to: " + AQUA + f"{api_keyab}" + RESET)
            banner()
            time.sleep(2)
        elif api_keyab_set.lower() in ('no', 'n'):
            nl()
            print("Keeping the current value of the AbuseIPDB API key")
            nl()
            banner()
        else:
            nl()
            print("Invalid input. Keeping the current value of the AbuseIPDB API key")
            nl()
            banner()


    write_api_keys(api_key, api_keyab)
    nl()

def execute_service(service, api_key, api_keyab):
    base_path = os.path.expanduser('~/VTscanner/')

    if service == '1':
        script_path = os.path.join(base_path, 'ipscheck.py')
        print(AQUA + "IPs Scanning Tool " + RESET + "was selected")
        print("Redirecting to " + AQUA + "IPs Scanning Tool" + RESET)
        arrow()
    elif service == '2':
        script_path = os.path.join(base_path, 'hashcheck.py')
        print(AQUA + "Files Scanning Tool " + RESET + "was selected")
        print("Redirecting to " + AQUA + "Files Scanning Tool" + RESET)
        arrow()
    elif service == '3':
        script_path = os.path.join(base_path, 'domainscheck.py')
        print(AQUA + "Domains Scanning Tool " + RESET + "was selected")
        print("Redirecting to " + AQUA + "Domains Scanning Tool" + RESET)
        arrow()
    elif service == '4':
    	script_path = os.path.join(base_path, 'sniff.py')
    	print(AQUA + "Traffic Capturing Tool " + RESET + "was selected")
    	print("Redirecting to " + AQUA + "Traffic Capturing Tool" + RESET)
    	arrow()
    else:
        print("Invalid choice. Please, select one of the provided services")
        script_path = os.path.join(base_path, 'VTscanner.py')

    try:
        subprocess.run(['python3', script_path, api_key, api_keyab])
        while True:
            choice = input("Service execution finished. Do you want to choose another service? (Yes/No): ")
            if choice.lower() in ('yes', 'y'):
                main()  # Return to the beginning of VTscanner.py for service selection
                break
            elif choice.lower() in ('no', 'n'):
                nl()
                banner()
                print("Alright! Thanks for using VTscanner! Have a nice one!")
                nl()
                banner()
                fin()
                break
            else:
                banner()
                nl()
                print("Invalid input. Please, select a valid option.")
                nl()
                banner()
    except KeyboardInterrupt:
        while True:
            nl()
            choice = input("Execution interrupted. Do you want to continue? (yes/no): ")
            nl()
            if choice.lower() in ('yes', 'y'):
                execute_service(service, api_key, api_keyab)
                break
            elif choice.lower() in ('no', 'n'):
                print("Alright! Exiting...")
                banner()
                fin()
                break
            else:
                banner()
                nl()
                print("Invalid input. Please, select a valid option")
                nl()
                banner()


def main():
    print(AQUA + "############            Welcome to VTscanner!            ############" + RESET)
    nl()
    api_key, api_keyab = read_api_keys()
    
    while True:
        print("Choose a service: ")
        nl()
        print("1. IPs scanning tool               "   + AQUA + f"(Type 1 to select this service)" + RESET)
        nl()
        print("2. Files scanning tool             "   + AQUA + f"(Type 2 to select this service)" + RESET)
        nl()
        print("3. Domains scanning tool           "   + AQUA + f"(Type 3 to select this service)" + RESET) 
        nl()
        print("4. Traffic Capturing tool          "   + AQUA + f"(Type 4 to select this service)" + RESET) 
        nl()
        service = input(":")
        nl()
        banner()
        if service in ('1', '2', '3', '4'):
            break
        else:
            time.sleep(0.5)
            banner()
            nl()
            print("Invalid input. Please, choose a valid service.")
            nl()
            banner()
            time.sleep(2)

    execute_service(service, api_key, api_keyab)


if __name__ == '__main__':
    check_api_keys()
    main()

