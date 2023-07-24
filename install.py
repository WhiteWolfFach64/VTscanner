#!/usr/bin/env python3

# Imports
import os
import shutil
import pwd
import grp
import time
import sys
import random
import subprocess

# Variables
RESET = "\033[0m"
AQUA = '\033[96m'
REDON = '\033[91m' 
YELLOW = "\033[93m"
PURPLE = "\033[95m"
ORANGE = "\033[38;5;208m"
BLUE = "\033[34m"

project_dir = os.path.dirname(os.path.abspath(__file__))
user_home_dir = os.path.expanduser("~" + os.getlogin())
target_dir = os.path.join(user_home_dir, "VTscanner")
link_path = "/usr/local/bin/VTscanner.py"
script_path = "~/VTscanner/VTscanner.py"
user_path = os.path.expanduser(script_path)

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


def setProjectDirectory():
    if project_dir == target_dir:
        progress_bar()
        print(REDON + "Project directory is already set." + RESET)
        time.sleep(1)
        return

    if os.path.exists(target_dir):
        progress_bar()
        print(AQUA + f"Target directory '{target_dir}' already exists." + RESET)
        time.sleep(1)
        return

    try:
        shutil.copytree(project_dir, target_dir)
        progress_bar()
        print(AQUA + f"Project directory copied to '{target_dir}'." + RESET)
        time.sleep(1)

        # Remove the original VTscanner directory
        if project_dir != target_dir and os.path.exists(project_dir):
            progress_bar()
            print(AQUA + f"Removing original VTscanner directory: '{project_dir}'..." + RESET)
            shutil.rmtree(project_dir)
            print(AQUA + "Original VTscanner directory removed." + RESET)
        time.sleep(1)

    except Exception as e:
        print(REDON + f"Failed to copy project directory: {e}" + RESET)

def create_symbolic_link(user_path, link_path):
    if os.path.islink(link_path):
        progress_bar()
        print(REDON + "Symbolic link already exists." + RESET)
        time.sleep(1)
    else:
        try:
            subprocess.run(['sudo', 'ln', '-s', user_path, link_path], check=True)
            progress_bar()
            print(AQUA + f"Symbolic link created: {link_path} -> {user_path}" + RESET)
            time.sleep(1)
        except subprocess.CalledProcessError as e:
            print(REDON + f"An error occurred: {e}" + RESET)
            time.sleep(1)

def set_executable_permissions(target_dir):
    vtscanner_path = os.path.join(target_dir, "VTscanner.py")
    os.chmod(vtscanner_path, 0o755)  # Set executable permissions
    progress_bar()
    print(AQUA + "Executable permissions given to 'VTscanner.py'" + RESET)
    time.sleep(1)

def change_ownership(target_dir):
    uid = pwd.getpwnam(os.getlogin()).pw_uid
    gid = grp.getgrnam(os.getlogin()).gr_gid

    # Change ownership recursively
    for root, dirs, files in os.walk(target_dir):
        os.chown(root, int(uid), gid)  # Change ownership of directories
        for file in files:
            file_path = os.path.join(root, file)
            os.chown(file_path, int(uid), gid)  # Change ownership of files
    time.sleep(1)

def progress_bar():
    toolbar_width = 40
    colors = ['\033[91m', '\033[93m', '\033[95m', '\033[38;5;208m', '\033[34m']
    color = random.choice(colors)

    sys.stdout.write(f"{color}[{' ' * toolbar_width}]\033[0m")
    sys.stdout.flush()
    sys.stdout.write("\b" * (toolbar_width+1))  # Return to start of line, after '['

    for i in range(toolbar_width):
        time.sleep(0.05)  # Simulating time-consuming task
        sys.stdout.write(f"{color}-\033[0m")
        sys.stdout.flush()

    sys.stdout.write(f"{color}]\033[0m\n")  # End of progress bar
    sys.stdout.flush()

def dots():
    for dots in range(3):
        print(".", end='', flush=True)
        time.sleep(1)
    print()

def banner():
    print("-" * 50)

def nl():
    print("\n")
    
def upgrade_and_install_libraries():
    progress_bar()
    try:
        # Upgrade pip3
        subprocess.run(['pip3', 'install', '--upgrade', 'pip'])

        # Install requests library
        subprocess.run(['pip3', 'install', 'requests'])

        # Install tldextract library
        subprocess.run(['pip3', 'install', 'tldextract'])

        progress_bar()
        print(AQUA + "Pip3 was upgraded and dependencies were installed" + RESET)
    except Exception as e:
        print(REDON + f"An error occurred: {e}" + RESET)

def nl():
    print("\n")

def DoInstall():
    if os.path.islink(link_path) and os.access(user_path, os.X_OK):
        print("VTscanner is already " + AQUA + "installed. " + RESET + "Would you like to " + AQUA + "uninstall " + RESET + "VTscanner?")
        while True:
            nl()
            print("1. Yes, please uninstall VTscanner from my computer   --------------> " + AQUA + "Type: uninstall" + RESET)
            nl()
            print("2. No, I would like to continue using VTscanner       --------------> " + AQUA + "Type: no" + RESET)
            nl()
            uninstall = input(":")
            
            if uninstall.lower() == "uninstall":
                print("Alright! Proceeding to uninstall VTscanner", end="")
                dots()
                progress_bar()
                time.sleep(1)

                # Undo Symbolic link /usr/local/bin ---> VTscanner.py
                command_link = "sudo rm -rf /usr/local/bin/VTscanner.py"
                process_link = subprocess.Popen(command_link, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout_link, stderr_link = process_link.communicate()  # Wait for the command to complete and fetch the output

                if process_link.returncode == 0:  # Check the return code to see if the command executed successfully
                    print("Symbolic link " + AQUA + f"{link_path} -> {user_path} " + RESET + "was undone.")
                else:
                    print("Symbolic link couldn't be undone. Reason: " + REDON + f"{stderr_link.decode().strip()}" + RESET)

                progress_bar()
                time.sleep(1)

                # Remove executable privileges from VTscanner.py
                command_execute = "chmod -x VTscanner.py"
                process_execute = subprocess.Popen(command_execute, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout_execute, stderr_execute = process_execute.communicate()  # Wait for the command to complete and fetch the output

                if process_execute.returncode == 0:  # Check the return code to see if the command executed successfully
                    print(AQUA + "Execution privileges removed for file VTscanner.py" + RESET)
                else:
                    print("Execution privileges could not be removed. Reason: " + REDON + f"{stderr_execute.decode().strip()}" + RESET)

                progress_bar()
                time.sleep(1)

                # Ask the user for hard deletion of VTscanner
                print("Would you like to remove VTscanner entirely from your computer? (Yes/No)")
                nl()
                print("(" + REDON + "!!!Warning!!!: " + RESET +  "Selecting " + REDON + "'Yes' " + RESET + "will hard delete VTscanner from your computer.") 
                print("If you wish to use VTscanner in the future, you'll have to download it again from: " + AQUA + "https://github.com/WhiteWolfFach64/VTscanner.git" + RESET + ")")

                while True:
                    nl()
                    DoRemove = input(":")
                    if DoRemove.lower() in ("yes", "y"):
                        # Remove VTscanner entirely from the computer
                        command_remove = f"sudo rm -rf {target_dir}"
                        process_remove = subprocess.Popen(command_remove, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout_remove, stderr_remove = process_remove.communicate()  # Wait for the command to complete and fetch the output

                        if process_remove.returncode == 0:  # Check the return code to see if the command executed successfully
                            print(AQUA + "VTscanner has been deleted from your computer" + RESET)
                            nl()
                            print("""
VTscanner was uninstalled. Have a nice day! 
                                          🐺""")
                        else:
                            print("Deletion of VTscanner was unsuccessful. Reason: " + REDON + f"{stderr_remove.decode().strip()}" + RESET)

                        break

                    elif DoRemove.lower() in ("no", "n"):
                        nl()
                        print("Alright! Keeping VTscanner on your computer")
                        nl()
                        time.sleep(2)
                        print("""
VTscanner was uninstalled. Have a nice day! 
                                          🐺""")
                        break

                    else:
                        banner()
                        nl()
                        print("Invalid input. Please, select a valid option")
                        nl()
                        banner()

                break

            elif uninstall.lower() == "no":
                nl()
                print("Alright! Exiting...")
                time.sleep(2)
                nl()
                print("""
VTscanner ready. Have a nice day! 
                                🐺""")
                sys.exit(0)

                break

            else:
                banner()
                nl()
                print("Invalid input. Please, select a valid option")
                nl()
                banner()

    else:
        # VTscanner is not installed. Starting installation.
        print("Preparing installation", end="")
        dots()
        setProjectDirectory()
        create_symbolic_link(user_path, link_path)
        set_executable_permissions(target_dir)
        change_ownership(target_dir)
        upgrade_and_install_libraries()
        nl()
        print("""
Installation complete. Have a nice day! 
                                      🐺""")



# ----- CODE EXECUTION --------------#
intro()
nl()
dots()
nl()
DoInstall()

