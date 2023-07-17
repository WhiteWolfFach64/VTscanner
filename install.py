#!/usr/bin/env python3

# Imports
import os
import shutil
import pwd
import grp
import time
import sys
import random

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
script_path = "/VTscanner.py"

# Functions
def setProjectDirectory():

    if project_dir == target_dir:
        progress_bar()
        print("Project directory is already set.")
        return

    if os.path.exists(target_dir):
        progress_bar()
        print(AQUA + f"Target directory '{target_dir}' already exists." + RESET)
        return

    try:
        shutil.copytree(project_dir, target_dir)
        progress_bar()
        print(AQUA + f"Project directory copied to '{target_dir}'." + RESET)
        time.sleep(1)

        create_symbolic_link(target_dir, script_path, link_path)
        set_executable_permissions(target_dir)
        change_ownership(target_dir)
        time.sleep(1)

        # Remove the original VTscanner directory
        if project_dir != target_dir and os.path.exists(project_dir):
            progress_bar()
            print(AQUA + f"Removing original VTscanner directory: '{project_dir}'..." + RESET)
            shutil.rmtree(project_dir)
            print(AQUA + "Original VTscanner directory removed." + RESET)
        time.sleep(1)

    except Exception as e:
        print(f"Failed to copy project directory: {e}")

def create_symbolic_link(target_dir, script_path, link_path):
    if os.path.exists(link_path):
        progress_bar()
        print(f"Symbolic link '{link_path}' already exists.")
    else:
        os.symlink(target_dir + script_path, link_path)
        progress_bar()
        print(AQUA + f"Symbolic link created: '{link_path}' -> '{target_dir + script_path}'" + RESET)

def set_executable_permissions(target_dir):
    vtscanner_path = os.path.join(target_dir, "VTscanner.py")
    os.chmod(vtscanner_path, 0o755)  # Set executable permissions
    progress_bar()
    print(AQUA + "Executable permissions given to 'VTscanner.py'" + RESET)

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


# ----- CODE EXECUTION --------------#
print("Preparing installation", end="")
dots()
setProjectDirectory()
create_symbolic_link(target_dir, script_path, link_path)
set_executable_permissions(target_dir)
change_ownership(target_dir)
nl()
print("""
Installation complete. Have a nice day! 

                                      🐺""")
