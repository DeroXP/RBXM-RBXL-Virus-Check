import os
import re
import tkinter as tk
from tkinter import filedialog
from tkinter import simpledialog
from colorama import init, Fore, Style

init(autoreset=True)

def check_lua_file(file_path, checks):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lua_code = file.read()
    except FileNotFoundError:
        print(Fore.RED + f"File not found: {file_path}")
        return
    except IOError:
        print(Fore.RED + f"Could not read file: {file_path}")
        return

    malicious_patterns = {
        "networking": re.compile(r'\bhttp\.request\b|\bsocket\.\b', re.IGNORECASE),
        "data_exfiltration": re.compile(r'\b(os\.execute\("curl\b|\bos\.execute\("wget\b|\bos\.execute\("nc\b)', re.IGNORECASE),
        "key_logging": re.compile(r'\b(io\.read\b|\bios\.open\b)', re.IGNORECASE),
        "environment_modification": re.compile(r'\b(os\.setenv\b|\bos\.remove\b|\bos\.rename\b|\bos\.execute\b)', re.IGNORECASE)
    }

    issues_found = False

    print(f"Checking {file_path}...")
    for behavior, pattern in malicious_patterns.items():
        if (behavior in checks or 'all' in checks) and pattern.search(lua_code):
            issues_found = True
            print(Fore.RED + f"Potential {behavior} behavior detected in {file_path}.")
    if not issues_found:
        print(Fore.GREEN + f"No potentially malicious behavior found in {file_path}.")

def main():
    root = tk.Tk()
    root.withdraw()

    checks = set()
    while True:
        check_type = simpledialog.askstring("Input", "Enter a behavior to check (networking, data_exfiltration, key_logging, environment_modification, all, deep), or type 'exit' to finish:")
        if check_type == 'exit':
            break
        if check_type not in ["networking", "data_exfiltration", "key_logging", "environment_modification", "all", "deep"]:
            print("Invalid behavior. Please choose from 'networking', 'data_exfiltration', 'key_logging', 'environment_modification', 'all', 'deep'.")
            continue
        checks.add(check_type)

        if 'all' in checks:
            checks = {"networking", "data_exfiltration", "key_logging", "environment_modification"}

        if not checks:
            print("No checks selected. Exiting.")
            return

        if 'deep' in checks:
            folder_path = filedialog.askdirectory()
            for dirpath, dirs, files in os.walk(folder_path):
                for filename in files:
                    if filename.endswith('.lua'):
                        file_path = os.path.join(dirpath, filename)
                        check_lua_file(file_path, checks)
        else:
            file_paths = filedialog.askopenfilenames(
                title="Select Lua files to check",
                filetypes=[("Lua files", "*.lua"), ("All files", "*.*")]
            )

            if not file_paths:
                print("No files selected.")
                return

            for file_path in file_paths:
                check_lua_file(file_path, checks)

if __name__ == "__main__":
    main()
