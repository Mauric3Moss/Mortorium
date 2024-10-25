import os
import re
import yara
import time

# Path to log file
LOG_FILE = 'malicious_files_log.txt'

# YARA rules file path
YARA_RULES_PATH = 'obfuscation_rules.yar'

# Regular expressions to detect obfuscated code patterns
OBFUSCATION_PATTERNS = [
    r'(?:\\x[0-9A-Fa-f]{2})+',  # Hex-encoded characters
    r'(?:\\u[0-9A-Fa-f]{4})+',  # Unicode escape sequences
    r'(?:\\[0-7]{1,3})+',       # Octal escape sequences
    r'(eval\(.*base64_decode\()',  # eval with base64_decode chain
    r'(eval\(.*rot13)',           # eval with ROT13
    r'(?:(?:\$|var|let|const)\s*[a-zA-Z0-9_]{1,2}\s*=)',  # Suspiciously short variable names
    r'(?:(?:\$|var|let|const)\s*[A-Za-z]{20,})',         # Unusually long variable names
    r'(String\.fromCharCode\([0-9,]+\))',  # String.fromCharCode() usage
    r'(unescape\([^\)]+\))',  # unescape() function
    r'(\)\s*\{[^\}]+\})',     # Excessive grouping or anonymous functions
]

# Function to load and compile YARA rules
def load_yara_rules():
    try:
        rules = yara.compile(filepath=YARA_RULES_PATH)
        return rules
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return None

# Function to check for obfuscation patterns using regex
def check_regex_obfuscation(file_contents):
    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, file_contents):
            return True
    return False

# Function to scan a file using YARA
def scan_file_with_yara(file_path, yara_rules):
    try:
        matches = yara_rules.match(file_path)
        if matches:
            return True
    except Exception as e:
        print(f"Error scanning {file_path} with YARA: {e}")
    return False

# Function to scan the file contents using both YARA and regex patterns
def scan_file(file_path, yara_rules):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            file_contents = file.read()

        # Check for obfuscation using regex patterns
        if check_regex_obfuscation(file_contents):
            log_malicious_file(file_path, "Regex Obfuscation Detected")
            return True

        # Check for obfuscation using YARA
        if yara_rules and scan_file_with_yara(file_path, yara_rules):
            log_malicious_file(file_path, "YARA Obfuscation Detected")
            return True

    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    
    return False

# Function to scan a directory recursively
def scan_directory(directory, yara_rules):
    malicious_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if scan_file(file_path, yara_rules):
                malicious_files.append(file_path)

    return malicious_files

# Function to log detected malicious files
def log_malicious_file(file_path, issue_type):
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"{time.ctime()}: {issue_type} - {file_path}\n")
    print(f"{issue_type}: {file_path}")

# Entry point of the script
if __name__ == '__main__':
    # Determine the root directory to scan based on the operating system
    if os.name == 'nt':  # For Windows
        directory_to_scan = 'C:\\'
    else:  # For Linux/macOS
        directory_to_scan = '/'

    # Load YARA rules
    yara_rules = load_yara_rules()

    # Clear previous log file contents
    with open(LOG_FILE, 'w') as log_file:
        log_file.write("Malicious file scan log\n")
        log_file.write("=======================\n\n")

    # Scan the root directory and log results
    print(f"Scanning the entire system: {directory_to_scan}")
    malicious_files = scan_directory(directory_to_scan, yara_rules)

    if malicious_files:
        print(f"Malicious files detected and logged to {LOG_FILE}")
    else:
        print("No malicious files detected.")
