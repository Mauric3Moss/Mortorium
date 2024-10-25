import os
import re
import yara
import time

# Path to log file
LOG_FILE = r'C:\\Users\\dtmin\\OneDrive\Desktop\\Projects\\GitRepos\\Mortorium\\logfiles\\malicious_files_log.txt'

# YARA rules file path
YARA_RULES_PATH = 'obfuscation_rules.yar'

# List of directories to ignore during the scan
IGNORED_DIRECTORIES = [
    'C:\\$Recycle.Bin',
    'C:\\ProgramData',
    'C:\\Windows',
    'C:\\Program Files',
    'C:\\Program Files (x86)',
    'C:\\Users\\dtmin\\.android',
    'C:\\Users\\dtmin\\.gradle',
    'C:\\Users\\dtmin\\.git',
    'C:\\Users\\dtmin\\.vscode',
    'C:\\Users\dtmin\AndroidStudioProjects',
    'C:\\Users\\dtmin\\AppData',

]

# Regular expressions for detecting obfuscation patterns
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

# Regular expressions for detecting potentially dangerous functions
DANGEROUS_FUNCTIONS = [
    r'cmd\.exe',               # Windows command execution
    r'powershell',             # PowerShell execution
    r'eval\(',                 # Possible code execution
    r'base64_decode\(',        # Base64 decoding (often used in malware)
    r'\bexec\b',               # Dangerous exec function
    r'<script>',               # Embedded script in files
    r'system\(',               # System command execution
    r'shell_exec\(',           # Shell command execution
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

# Function to check for dangerous function patterns using regex
def check_dangerous_functions(file_contents):
    for pattern in DANGEROUS_FUNCTIONS:
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

        # Check for dangerous functions using regex patterns
        if check_dangerous_functions(file_contents):
            log_malicious_file(file_path, "Dangerous Function Detected")
            return True

        # Check for obfuscation using YARA
        if yara_rules and scan_file_with_yara(file_path, yara_rules):
            log_malicious_file(file_path, "YARA Obfuscation Detected")
            return True

    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    
    return False

# Function to scan a directory recursively, excluding specified directories
def scan_directory(directory, yara_rules):
    malicious_files = []
    for root, dirs, files in os.walk(directory):
        # Exclude ignored directories
        if any(ignored_dir in root for ignored_dir in IGNORED_DIRECTORIES):
            continue

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

# Ensure the log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

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
