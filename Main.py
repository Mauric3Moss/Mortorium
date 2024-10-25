import os
import re
import time

# Define suspicious patterns to look for in file contents
SUSPICIOUS_PATTERNS = [
    r'cmd\.exe',           # Windows command execution
    r'powershell',         # Powershell execution
    r'eval\(',             # Possible code execution
    r'base64_decode\(',    # Base64 decoding (often used in malware)
    r'\bexec\b',           # Dangerous exec function
    r'<script>',           # Embedded script in files
    r'system\(',           # System command execution
    r'shell_exec\(',       # Shell execution
    r'obfuscation',        # Placeholder for obfuscated code detection
    # Add more patterns as needed
]

# Path to log file
LOG_FILE = 'malicious_files_log.txt'

# Function to check if a file contains malicious patterns
def scan_file_contents(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            contents = f.read()
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, contents, re.IGNORECASE):
                    return True
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return False

# Function to scan a directory for files with suspicious contents
def scan_directory(directory):
    malicious_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if scan_file_contents(file_path):
                malicious_files.append(file_path)
                log_malicious_file(file_path)

    return malicious_files

# Function to log malicious file locations
def log_malicious_file(file_path):
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"{time.ctime()}: Suspicious file detected - {file_path}\n")

# Entry point
if __name__ == '__main__':
    # Define the directory you want to scan
    directory_to_scan = 'C:\\Users\\-----\\OneDrive\\Desktop\\Projects\\homework'  # Change this to your desired path

    # Clear previous log file contents
    with open(LOG_FILE, 'w') as log_file:
        log_file.write("Malicious file scan log\n")
        log_file.write("=======================\n\n")

    # Scan the directory and log results
    print(f"Scanning directory: {directory_to_scan}")
    malicious_files = scan_directory(directory_to_scan)

    if malicious_files:
        print(f"Malicious files detected and logged to {LOG_FILE}")
    else:
        print("No malicious files detected.")
