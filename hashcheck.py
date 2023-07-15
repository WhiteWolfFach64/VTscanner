#!/usr/bin/env python3

# Imports
import os
import sys
import re
import time
import requests
import ipaddress
import json
import hashlib
import urllib.parse

# Global Variables
API_KEY = sys.argv[1]
RED = "\033[41m"
GREEN = "\033[42m"
BLACK = "\033[30m"
RESET = "\033[0m"
AQUA = '\033[96m'
ORANGE = "\033[33m"
REDON = "\033[31m"

# Functions
def intro():
    intro = AQUA + r"""
|-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-|

   _,_ ___  _,  _,  _, _, _ _, _ __, __,
   | /  |  (_  / ` /_\ |\ | |\ | |_  |_)
   |/   |  , ) \ , | | | \| | \| |   | \
   ~    ~   ~   ~  ~ ~ ~  ~ ~  ~ ~~~ ~ ~  

File Scanning Tool                      By WhiteWolf 🐺

|-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-||-|
""" + RESET
    print(intro)

def fin():
    banner()
    print(AQUA + "FIN" + RESET)

def exit():
	time.sleep(3)
	banner()
	fin()
	sys.exit(0)

def nl():
    print("\n")

def banner():
    print("-" * 50)

def dots():
    for dots in range(3):
        print(".", end='', flush=True)
        time.sleep(1)
    print()

def loadingBar():
    total_progress = 100
    for progress in range(total_progress + 1):
        time.sleep(0.05)  # Add a small delay to visualize the progress
        percent = progress * 100 // total_progress
        bar = "[" + "#" * (progress // 10) + " " * ((total_progress - progress) // 10) + "]"
        print(f"Progress: {percent}% {bar}", end="\r", flush=True)
    time.sleep(1)
    print("\nLoading complete!")
    time.sleep(1)
    
def arrow():
    for dots in range(35):
        print("-", end='', flush= True)
        time.sleep(0.05)
    print(">   Done!")
    
def fileOrHash():
    while True:
        fileOrHash = input("""
Do you want to scan a file or provide a list of hashes?
1 ----------------------> Scan a file
2 ----------------------> Provide a list of hashes
""")
        if fileOrHash in ['1']:
            print("Redirecting to file scanner")
            arrow()
            fileScanner()
            break
        elif fileOrHash in ['2']:
            print("Redirecting to hash scanner")
            arrow()
            hashScanner()
            break
        else:
            print("Invalid input. Please select a valid option.")

def hashScanner():
    chooseFile = input("Choose a file: ")
    filePath = os.path.expanduser(f"~/VTscanner/txt/{chooseFile}")  # Update the file path
    if os.path.exists(filePath):
        foundFile = filePath
        print("File found:", foundFile)
        banner()
        print("Proceeding to scan file", end="")
        dots()
        nl()
        print("Reading file and extracting hashes")
        with open(filePath, 'r') as file:
            lines = file.readlines()
    else:
        print("File not found. Exiting...")
        nl()
        sys.exit(1)

    loadingBar()
    time.sleep(1)

    hashes = {'MD5': [], 'SHA1': [], 'SHA256': []}

    for line in lines:
        line = line.strip()

        md5_matches = re.findall(r"\b[0-9a-fA-F]{32}\b", line)
        sha1_matches = re.findall(r"\b[0-9a-fA-F]{40}\b", line)
        sha256_matches = re.findall(r"\b[0-9a-fA-F]{64}\b", line)

        hashes['MD5'].extend(md5_matches)
        hashes['SHA1'].extend(sha1_matches)
        hashes['SHA256'].extend(sha256_matches)

    banner()
    print("Here is the list of " + AQUA + str(len(hashes['MD5'])) + RESET + " unique MD5 hashes in file " + AQUA + f"{chooseFile}" + RESET)
    for MD5_hash in hashes['MD5']:
        print(AQUA + MD5_hash + RESET, "\n")

    banner()
    print("Here is the list of " + AQUA + str(len(hashes['SHA1'])) + RESET + " unique SHA1 hashes in file " + AQUA + f"{chooseFile}" + RESET)
    for SHA1_hash in hashes['SHA1']:
        print(AQUA + SHA1_hash + RESET, "\n")

    banner()
    print("Here is the list of " + AQUA + str(len(hashes['SHA256'])) + RESET + " unique SHA256 hashes in file " + AQUA + f"{chooseFile}" + RESET)
    for SHA256_hash in hashes['SHA256']:
        print(AQUA + SHA256_hash + RESET, "\n")

    hash_counts = [str(len(hashes['MD5'])), str(len(hashes['SHA1'])), str(len(hashes['SHA256']))]

    if any(int(count) > 0 for count in hash_counts):
        pass
    else:
        print("No hashes were found. Have a nice day!")
        banner()
        fin()
        sys.exit(0)

    while True:
        hashesUpload = input("Would you like to upload this list of hashes to VT? (Yes/No)\n")

        if hashesUpload.lower() in ['yes', 'y']:
            for SHA256_hash in hashes['SHA256']:
                API_URLVT_SHA256 = f"https://www.virustotal.com/api/v3/files/{SHA256_hash}"
                headers_SHA256 = {
                    "accept": "application/json",
                    "x-apikey": API_KEY
                }
                response = requests.get(API_URLVT_SHA256, headers=headers_SHA256)
                banner()
                nl()
                if response.status_code == 200:  # Check if the response is successful
                    response_data = response.json()  # Extract JSON data from the response
                    if 'data' in response_data:  # Check if 'data' field exists in the response
                        maliciousFlag = response_data['data']['attributes']['last_analysis_stats']['malicious']
                        if maliciousFlag > 0:
                            print(AQUA + f"{SHA256_hash} : " + RESET + RED + BLACK + f"Hash associated to malicious file!" + RESET + AQUA + f" {maliciousFlag} " + RESET + "vendors flagged this file hash " + RESET + "as malicious. Proceed to manual scan!")
                        else:
                            print("Hash " + AQUA + f"{SHA256_hash} " + RESET + "is clean!")
                    else:
                        print("This file could not be identified on VT.")
                else:
                    print("Failed to retrieve information from VT.")

            for SHA1_hash in hashes['SHA1']:
                API_URLVT_SHA1 = f"https://www.virustotal.com/api/v3/files/{SHA1_hash}"
                headers_SHA1 = {
                    "accept": "application/json",
                    "x-apikey": API_KEY
                }
                response = requests.get(API_URLVT_SHA1, headers=headers_SHA1)
                banner()
                nl()
                if response.status_code == 200:  # Check if the response is successful
                    response_data = response.json()  # Extract JSON data from the response
                    if 'data' in response_data:  # Check if 'data' field exists in the response
                        maliciousFlag = response_data['data']['attributes']['last_analysis_stats']['malicious']
                        if maliciousFlag > 0:
                            print(AQUA + f"{SHA1_hash} : " + RESET + RED + BLACK + f"Malicious file!" + RESET + AQUA + f" {maliciousFlag} " + RESET + "vendors flagged file " + AQUA + f"{chooseFile} " + RESET + "as malicious. Proceed to manual scan!")
                        else:
                            print("Hash " + AQUA + f"{SHA1_hash} " + RESET + "is clean!")
                    else:
                        print("This file could not be identified on VT.")
                else:
                    print("Failed to retrieve information from VT.")

            for MD5_hash in hashes['MD5']:
                API_URLVT_MD5 = f"https://www.virustotal.com/api/v3/files/{MD5_hash}"
                headers_MD5 = {
                    "accept": "application/json",
                    "x-apikey": API_KEY
                }
                response = requests.get(API_URLVT_MD5, headers=headers_MD5)
                banner()
                nl()
                if response.status_code == 200:  # Check if the response is successful
                    response_data = response.json()  # Extract JSON data from the response
                    if 'data' in response_data:  # Check if 'data' field exists in the response
                        maliciousFlag = response_data['data']['attributes']['last_analysis_stats']['malicious']
                        if maliciousFlag > 0:
                            print(AQUA + f"{MD5_hash} : " + RESET + RED + BLACK + f"Malicious file!" + RESET + AQUA + f" {maliciousFlag} " + RESET + "vendors flagged file " + AQUA + f"{chooseFile} " + RESET + "as malicious. Proceed to manual scan!")
                        else:
                            print("File " + AQUA + f"{MD5_hash} " + RESET + "is clean!")
                    else:
                        print("This file could not be identified on VT.")
                else:
                    print("Failed to retrieve information from VT.")

            break  # Exit the while loop after processing hashes
        elif hashesUpload.lower() in ['no', 'n']:
            print("Alright! Exiting...")
            nl()
            sys.exit(0)
        else:
            banner()
            nl()
            print("Invalid input. Please select a valid option.")
            nl()
            banner()

def fileScanner():
    chooseFile = input("Choose a file: ")
    filePath = os.path.expanduser(f"~/VTscanner/txt/{chooseFile}")
    if os.path.exists(filePath):
        foundFile = filePath
        print("File found:", foundFile)
        banner()
        print("Proceeding to scan file", end="")
        dots()
        nl()
        print("Extracting file hash")
        with open(foundFile, "rb") as file:
            sha256Hash = hashlib.sha256(file.read()).hexdigest()
        loadingBar()
        nl()
        print("Here is the hash for file " + AQUA + f"{chooseFile}" + RESET + ": " + AQUA + f"{sha256Hash}" + RESET)
        banner()

        while True:
            DoUpload = input("Would you like to upload this hash to VT for scanning? (Yes/No): ")
            nl()

            if DoUpload.lower() in ['yes', 'y']:
                API_URLVT = f"https://www.virustotal.com/api/v3/files/{sha256Hash}"
                headers = {
                    "accept": "application/json",
                    "x-apikey": API_KEY
                }
                response = requests.get(API_URLVT, headers=headers)

                if response.status_code == 200:  # Check if the response is successful
                    response_data = response.json()  # Extract JSON data from the response
                    if 'data' in response_data:  # Check if 'data' field exists in the response
                        maliciousFlag = response_data['data']['attributes']['last_analysis_stats']['malicious']
                        if maliciousFlag > 0:
                            print(RED + BLACK + "Malicious file!" + RESET + AQUA + F" {maliciousFlag} " + RESET + "vendors flagged file " + AQUA + f"{chooseFile} " + RESET + "as malicious. Proceed to manual scan!")
                            break
                                  
                        else:
                            print("File " + AQUA + f"{chooseFile} " + RESET + "is clean!")
                            break
                    else:
                        print("This file could not be identified on VT.")
                        uploadFileToVT(chooseFile, filePath, sha256Hash)  # Call the function to upload file to VT
                else:
                    print("Failed to retrieve information from VT.")
                    uploadFileToVT(chooseFile, filePath, sha256Hash)  # Call the function to upload file to VT
                    break
            elif DoUpload.lower() in ['no', 'n']:
                print("Alright! Exiting...")
                nl()
                exit()
                break
            else:
                banner()
                nl()
                print("Invalid input. Please, select a valid option.")
                nl()
                banner()
    else:
        print("File not found. Exiting...")
        nl()
        exit()

def uploadFileToVT(chooseFile, filePath, sha256Hash):
    nl()
    banner()
    while True:
        uploadToVT = input("Would you like to upload the file " + AQUA + f"{chooseFile} " + RESET + "to VT? (Yes/No): ")
        if uploadToVT.lower() in ['yes', 'y']:
            print(f"Scanning file selected " + AQUA + f"{chooseFile}" + RESET)
            # Obtain URL for larger file
            url_larger_file = "https://www.virustotal.com/api/v3/files/upload_url"
            headers_larger_file = {
                "accept": "application/json",
                "x-apikey": API_KEY
            }
            response_larger_file = requests.get(url_larger_file, headers=headers_larger_file)
            if response_larger_file.status_code == 200:
                reponse_data_larger_file = response_larger_file.json()
                # Encoding for larger files and send the file to that URL
                url_upload_file = reponse_data_larger_file['data']
                encoded_chooseFile_larger_file = urllib.parse.quote(chooseFile)
                encoded_filePath_larger_file = urllib.parse.quote(filePath)
                url_upload_file = f"{url_upload_file}"
                file_upload_file = {"file": (f"{encoded_chooseFile_larger_file}", open(f"{encoded_filePath_larger_file}", "rb"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
                headers_upload_file = {
                    "accept": "application/json",
                    "x-apikey": API_KEY
                }
                response_upload_file = requests.post(url_upload_file, files=file_upload_file, headers=headers_upload_file)
                response_data_upload_file = response_upload_file.json()
                #print(response_data_upload_file['data']['id'])
                # Insert progress bar here
                nl()
                total_progress = 100
                print("Scanning file. Please wait...")
                for progress in range(total_progress + 1):
                    time.sleep(0.5)  # Add a small delay to visualize the progress
                    percent = progress * 100 // total_progress
                    bar = "[" + "#" * (progress // 10) + " " * ((total_progress - progress) // 10) + "]"
                    print(f"Progress: {percent}% {bar}", end="\r", flush=True)
                nl()
                print("\nScan complete!")
                time.sleep(1)
                if response_upload_file.status_code == 200:
                    response_data_upload_file = response_upload_file.json()
                    # URL encode ID to get analysis report
                    url_encode_analysis = urllib.parse.quote(response_data_upload_file['data']['id'])
                    #print(url_encode_analysis)
                    url_analysis = f"https://www.virustotal.com/api/v3/analyses/{url_encode_analysis}"
                    headers_analysis = {
                        "accept": "application/json",
                        "x-apikey": API_KEY
                    }
                    response_analysis = requests.get(url_analysis, headers=headers_analysis)
                    response_data_analysis = response_analysis.json()
                    #print(response_data_analysis['data']['attributes']['status'])
                    #print(response_data_analysis['data']['attributes']['stats']['malicious'])
                    #print(response_data_analysis['data']['attributes']['stats']['suspicious'])
                    # If status is queued, ask again in a while
                    response_data_analysis_again = None  # Initialize the variable
                    while response_data_analysis['data']['attributes']['status'] == "queued":
                        nl()
                        banner()
                        print("Extracting data. Please wait", end="")
                        dots()
                        response_analysis_again = requests.get(url_analysis, headers=headers_analysis)  # Asking again
                        response_data_analysis_again = response_analysis_again.json()
                        nl()
                        banner()
                        print("Results:")
                        if response_data_analysis_again is not None:
                            nl()
                            print("Status: " + AQUA + response_data_analysis_again['data']['attributes']['status'] + RESET)
                            if response_data_analysis_again['data']['attributes']['status'] == "completed":
                                break  # Break the loop when status is "completed"
                        nl()
                        print("Status is still " + AQUA + "queued. " + RESET +  "Sending request again", end ="")
                        dots()
                    else:
                        nl()
                        banner()
                        print("Status : " + AQUA + response_data_analysis['data']['attributes']['status'] + RESET)
                        print("Flagged as malicious: " + REDON + str(response_data_analysis['data']['attributes']['stats']['malicious']) + RESET)
                        print("Flagged as suspicious: " + ORANGE + str(response_data_analysis['data']['attributes']['stats']['suspicious']) + RESET)
                        if response_data_analysis['data']['attributes']['stats']['malicious'] > 0:
                            countMalicious = response_data_analysis['data']['attributes']['stats']['malicious']
                            nl()
                            print(RED + BLACK + f"Malicious file!" + RESET + AQUA + F" {countMalicious} " + RESET + "vendors flagged file " + AQUA + f"{chooseFile} " + RESET + "as malicious. Proceed to manual scan!")
                        elif response_data_analysis['data']['attributes']['stats']['malicious'] <= 0 and response_data_analysis['data']['attributes']['stats']['suspicious']:
                            countSuspicious = response_data_analysis['data']['attributes']['stats']['suspicious']
                            nl()
                            print(RED + BLACK + f"Suspicious file!" + RESET + AQUA + F" {countSuspicious} " + RESET + "vendors flagged file " + AQUA + f"{chooseFile} " + RESET + "as malicious. Proceed to manual scan!")
                        else:
                            nl()
                            print("File " + AQUA + f"{chooseFile} " + RESET + "is clean!")
                if response_data_analysis_again is not None:
                    nl()
                    banner()
                    print("Results:")
                    nl()
                    print("Status: " + AQUA + response_data_analysis_again['data']['attributes']['status'] + RESET)
                    print("Flagged as malicious: " + REDON + str(response_data_analysis_again['data']['attributes']['stats']['malicious']) + RESET)
                    print("Flagged as suspicious: " + ORANGE + str(response_data_analysis_again['data']['attributes']['stats']['suspicious']) + RESET)
                    if response_data_analysis_again['data']['attributes']['stats']['malicious'] > 0:
                        countMalicious = response_data_analysis_again['data']['attributes']['stats']['malicious']
                        nl()
                        print(RED + BLACK + f"Malicious file!" + RESET + AQUA + F" {countMalicious} " + RESET + "vendors flagged file " + AQUA + f"{chooseFile} " + RESET + "as malicious. Proceed to manual scan!")
                        break
                    elif response_data_analysis_again['data']['attributes']['stats']['malicious'] <= 0 and response_data_analysis['data']['attributes']['stats']['suspicious']:
                        countSuspicious = response_data_analysis_again['data']['attributes']['stats']['suspicious']
                        nl()
                        print(RED + BLACK + f"Suspicious file!" + RESET + AQUA + F" {countSuspicious} " + RESET + "vendors flagged file " + AQUA + f"{chooseFile} " + RESET + "as malicious. Proceed to manual scan!")
                        break
                    else:
                        nl()
                        print("File " + AQUA + f"{chooseFile} " + RESET + "is clean!")
                        break
            else:
                nl()
                print("It was not possible to upload the file")
                break
        elif uploadToVT.lower() in ['no', 'n']:
            nl()
            banner()
            print("Alright! Exiting...")
            nl()
            exit()
            break
        else:
            banner()
            nl()
            print("Invalid input. Please select a valid option.")
            nl()
            banner()

	
# -- CODE EXECUTION  --  #

# Intro to code
intro()
banner()
fileOrHash()
banner()
fin()

