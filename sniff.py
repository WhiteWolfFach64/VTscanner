#!/usr/bin/python3

import os
import subprocess
import threading
import warnings

def get_available_interfaces():
    try:
        result = subprocess.check_output(["ifconfig"]).decode()
        interfaces = [line.split(":")[0] for line in result.splitlines() if "flags=" in line]
        return interfaces
    except subprocess.CalledProcessError:
        return []

def get_default_terminal_command():
    for terminal in ["x-terminal-emulator", "gnome-terminal", "konsole", "xterm", "lxterminal", "terminator"]:
        try:
            subprocess.check_output(["which", terminal])
            return terminal
        except subprocess.CalledProcessError:
            pass
    return "x-terminal-emulator"

def tshark_capture(interface, output_file):
    try:
        message1 = f"Capturing traffic on {interface}... | Project Name: '{output_file}' | Traffic captured being saved in: ~/VTscanner/txt/{output_file}"
        message2 = "To stop capturing traffic please press Ctrl + C\n"

        tshark_cmd = [
            "tshark",
            "-i", interface,
            "-q",  # Quiet mode
            "-w", os.path.expanduser(f"~/VTscanner/txt/{output_file}.pcap"),  # Output file path
        ]

        terminal_cmd = get_default_terminal_command()

        # Construct the complete command with stderr redirected to /dev/null
        cmd_to_execute = f"echo '{message1}' && echo '{message2}' && {' '.join(tshark_cmd)} 2>/dev/null"

        process = subprocess.Popen([terminal_cmd, "-e", "bash", "-c", cmd_to_execute], shell=False)
        process.wait()  # Wait for the child process to complete

    except subprocess.CalledProcessError:
        print("Tshark is not installed or could not be found.")
        return

    print("This script worked!")

def tshark():
    try:
        subprocess.check_output(["which", "tshark"]).decode().strip()
    except subprocess.CalledProcessError:
        print("Tshark is not installed or could not be found.")
        return

    interfaces = get_available_interfaces()
    if not interfaces:
        print("No network interfaces found.")
        return

    print("Available network interfaces:")
    for i, interface in enumerate(interfaces, 1):
        print(f"{i}. {interface}")

    while True:
        try:
            selection = int(input("Enter the number of the interface to capture traffic: "))
            if 1 <= selection <= len(interfaces):
                selected_interface = interfaces[selection - 1]
                break
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    output_file = input("Please, select a name for the project (Type a string: '')")

    print(f"Capturing traffic on {selected_interface}... | Project Name: '{output_file}' | Traffic captured being saved in: ~/VTscanner/txt/{output_file}")

    # Suppress warnings temporarily
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        threading.Thread(target=tshark_capture, args=(selected_interface, output_file)).start()

if __name__ == "__main__":
    tshark()
