#!/usr/bin/env python3

import os
import shutil
import pwd
import grp

def setProjectDirectory():
    project_dir = os.path.dirname(os.path.abspath(__file__))
    user_home_dir = os.path.expanduser("~" + os.getlogin())
    target_dir = os.path.join(user_home_dir, "VTscanner")
    link_path = "/usr/local/bin/VTscanner"
    script_path = "/VTscanner.py"

    if project_dir == target_dir:
        print("Project directory is already set.")
        return

    if os.path.exists(target_dir):
        print(f"Target directory '{target_dir}' already exists.")
        return

    try:
        shutil.copytree(project_dir, target_dir)
        print(f"Project directory copied to '{target_dir}'.")

        if os.path.exists(link_path):
            print(f"Symbolic link '{link_path}' already exists.")
        else:
            os.symlink(target_dir + script_path, link_path)
            print(f"Symbolic link created: '{link_path}' -> '{target_dir + script_path}'")

        uid = pwd.getpwnam(os.getlogin()).pw_uid
        gid = grp.getgrnam(os.getlogin()).gr_gid

        # Change ownership recursively
        for root, dirs, files in os.walk(target_dir):
            os.chown(root, int(uid), gid)  # Change ownership of directories
            for file in files:
                file_path = os.path.join(root, file)
                os.chown(file_path, int(uid), gid)  # Change ownership of files

        # Remove the original VTscanner directory
        if project_dir != target_dir and os.path.exists(project_dir):
            print(f"Removing original VTscanner directory: '{project_dir}'...")
            shutil.rmtree(project_dir)
            print("Original VTscanner directory removed.")

    except Exception as e:
        print(f"Failed to copy project directory: {e}")

# Execute function
setProjectDirectory()


