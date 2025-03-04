import hashlib
import os
import json

HASH_FILE = r"C:\\Users\\rajar\\OneDrive\\Desktop\\test_files\\file_hashes.json"

def calculate_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return None

def save_hashes(hashes):
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

def load_hashes():
    if not os.path.exists(HASH_FILE) or os.stat(HASH_FILE).st_size == 0:
        print("[WARNING] Hash file is missing or empty. Initializing a new one.")
        return {}

    try:
        with open(HASH_FILE, "r") as f:
            data = f.read().strip()
            if not data:
                print("[WARNING] Hash file is empty. Resetting file hashes.")
                return {}
            return json.loads(data)
    except (json.JSONDecodeError, ValueError):
        print("[ERROR] Corrupted JSON file. Resetting file hashes.")
        return {}

def initialize_monitor(directory):
    hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file == "C:\\Users\\rajar\\OneDrive\\Desktop\\test_files\\file_hashes.json":
                continue
            file_path = os.path.join(root, file)
            hashes[file_path] = calculate_hash(file_path)
    save_hashes(hashes)
    print("Initial file hashes have been saved.")

def check_integrity():
    old_hashes = load_hashes()
    new_hashes = {}
    changed_files = []
    new_files = []

    for file_path in old_hashes.keys():
        new_hash = calculate_hash(file_path)
        if new_hash is None:
            print(f"[DELETED] {file_path}")
        elif new_hash != old_hashes[file_path]:
            print(f"[MODIFIED] {file_path}")
            changed_files.append(file_path)
        new_hashes[file_path] = new_hash

    for root, _, files in os.walk(os.path.dirname(HASH_FILE)):
        for file in files:
            if file == "C:\\Users\\rajar\\OneDrive\\Desktop\\test_files\\file_hashes.json":
                continue
            file_path = os.path.join(root, file)
            if file_path not in old_hashes:
                new_hash = calculate_hash(file_path)
                if new_hash:
                    new_hashes[file_path] = new_hash
                    print(f"[NEW FILE] {file_path}")
                    new_files.append(file_path)

    save_hashes(new_hashes)
    
    if not changed_files and not new_files:
        print("No file integrity issues detected.")
    else:
        print("File integrity issues detected!")

if __name__ == "__main__":
    directory_to_monitor = r"C:\\Users\\rajar\\OneDrive\\Desktop\\test_files"
    if not os.path.exists(HASH_FILE) or os.stat(HASH_FILE).st_size == 0:
        initialize_monitor(directory_to_monitor)
    else:
        check_integrity()
