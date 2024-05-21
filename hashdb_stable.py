import hashlib
import itertools
from tqdm import tqdm
import time
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
import sqlite3
import mmap

def hash_password(password, hash_type):
    hash_func = hashlib.new(hash_type)
    hash_func.update(password.encode())
    return hash_func.hexdigest()

def select_file(file_path):
    while True:
        file_path = file_path.strip()
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
        if os.path.exists(file_path):
            return file_path
        else:
            print("File not found. Please enter a valid file path.")

def clear_terminal():
    if os.name == 'posix':  # Unix/Linux/MacOS
        os.system('clear')
    elif os.name == 'nt':   # Windows
        os.system('cls')
    else:
        print("Unsupported operating system.")

def list_hash_algorithms():
    return hashlib.algorithms_guaranteed

def select_hash_type(hash_type_desired):
    algorithms = list_hash_algorithms()
    print("\n[?] For available algorithms, use the 'list types' command.")
    hash_type = hash_type_desired.strip().lower()
    if hash_type in algorithms:
        print("\n[+] Selected", hash_type)
        return hash_type
    else:
        print("Invalid hash type. Please select a valid hash algorithm from the list (list types).")

def stream_file(file_path):
    try:
        with open(file_path, "r") as f:
            for line in f:
                item = line.strip()
                if item:
                    yield item
    except FileNotFoundError:
        print("\n[!] File not found. Please provide valid path.")
        return None

def estimate_time(start_time, processed_words, total_words):
    elapsed_time = time.time() - start_time
    rate = processed_words / elapsed_time if elapsed_time > 0 else 0
    remaining_words = total_words - processed_words
    estimated_time = remaining_words / rate if rate > 0 else float('inf')
    
    hours, remainder = divmod(estimated_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if hours >= 1:
        return f"{int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"
    elif minutes >= 1:
        return f"{int(minutes)} minutes, {int(seconds)} seconds"
    else:
        return f"{estimated_time:.2f} seconds"

def crack_hash_worker(password, hash_type):
    hashed_password = hash_password(password, hash_type)
    return password, hashed_password

def process_batch(batch, hash_type):
    results = []
    for password in batch:
        hashed_password = hash_password(password[0], hash_type)
        results.append((password[0], hashed_password))
    return results

def crack_hashes(password_db, hash_db, hash_type, password_table, verbose=False):
    table_grab_name = hash_type + "hashes"
    print("\n[*] Beginning attempt...\n")
    
    with sqlite3.connect(hash_db) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT hash FROM {table_grab_name}")
        hashes = set(row[0] for row in cursor.fetchall())

    if not hashes:
        print("\n[!] No hashes found. Exiting...")
        return

    print(f"[+] Loaded {len(hashes)} hashes")
    
    with sqlite3.connect(password_db) as password_conn:
        password_cursor = password_conn.cursor()
        
        # Debugging: List all tables in the database
        password_cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = password_cursor.fetchall()
        # print(f"[DEBUG] Available tables in {password_db}: {tables}") available debug statement for table issues
        
        password_cursor.execute(f"SELECT COUNT(*) FROM {password_table}")
        total_passwords = password_cursor.fetchone()[0]
        print(f"[+] Loaded {total_passwords} passwords from {password_table}")

    start_time = time.time()
    processed_passwords = 0
    found_passwords = {}
    batch_size = 10000  # Process passwords in batches

    with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []
        while True:
            with sqlite3.connect(password_db) as password_conn:
                password_cursor = password_conn.cursor()
                password_cursor.execute(f"SELECT password FROM {password_table} LIMIT ? OFFSET ?", (batch_size, processed_passwords))
                batch = password_cursor.fetchall()
                
            if not batch:
                break
                
            future = executor.submit(process_batch, batch, hash_type)
            futures.append(future)
            processed_passwords += len(batch)

            for future in as_completed(futures):
                results = future.result()
                for password, hashed_password in results:
                    if verbose:
                        print(f"[HashDB] {hashed_password} -> {{ {password} }}")

                    if hashed_password in hashes:
                        found_passwords[hashed_password] = password
                        hashes.remove(hashed_password)
                        print(f"\033[92mPassword found: {password} for hash: {hashed_password}\033[0m")

                        # Insert found hash into KnownHashes table
                        with sqlite3.connect(hash_db) as conn:
                            cursor = conn.cursor()
                            cursor.execute("INSERT OR IGNORE INTO KnownHashes (hash, password, hash_type) VALUES (?, ?, ?)", (hashed_password, password, hash_type))
                            conn.commit()

                futures.remove(future)

                if not hashes:
                    break

            if processed_passwords % 50000 == 0:  # Adjust this number for frequency of updates
                estimated_time = estimate_time(start_time, processed_passwords, total_passwords)
                sys.stdout.write(f"\rProcessed {processed_passwords}/{total_passwords} words. Estimated time remaining: {estimated_time}.")
                sys.stdout.write(f"\nHashes found: {len(found_passwords)}/{len(hashes)}\033[F")
                sys.stdout.flush()

        # Ensure all remaining futures are processed
        for future in as_completed(futures):
            results = future.result()
            for password, hashed_password in results:
                if verbose:
                    print(f"[HashDB] {hashed_password} -> {{ {password} }}")

                if hashed_password in hashes:
                    found_passwords[hashed_password] = password
                    hashes.remove(hashed_password)
                    print(f"\033[92mPassword found: {password} for hash: {hashed_password}\033[0m")

                    # Insert found hash into KnownHashes table
                    with sqlite3.connect(hash_db) as conn:
                        cursor = conn.cursor()
                        cursor.execute("INSERT OR IGNORE INTO KnownHashes (hash, password, hash_type) VALUES (?, ?, ?)", (hashed_password, password, hash_type))
                        conn.commit()

    estimated_time = estimate_time(start_time, processed_passwords, total_passwords)
    print(f"\nProcessed {processed_passwords}/{total_passwords} words. Estimated time remaining: {estimated_time}.")
    print(f"Hashes found: {len(found_passwords)}/{len(hashes)}")

    if hashes:
        print(f"Could not find passwords for the following hashes: {list(hashes)}")
    else:
        print("All hashes cracked.")

def display_help_menu():
    print("""
    Commands:
    - create [-w/-h (wordlist or hash list)] [databaseName] [hash_type (leave blank if using -w)]: Create a new database.
    - delete [-d] [databaseName]: Delete an existing database.
    - start [passwordListDatabase] [targetHashDatabase] [hashType]: Start the hash cracking process.
    - set type <hash_type>: Set the hash type (e.g., md5, sha1).
    - load hashlist <file_path> <targetDB> <hashType>: Load hashes from a file into the specified database and table.
    - load wordlist <file_path> <targetDB>: Load passwords from a file into the specified database and table.
    - set verbose <on/off>: Enable or disable verbose output.
    - exit: Exit the program.
    - help: Display this help menu.
    """)

def delete_table(del_database_name):
    # Ensure the database name has the .db extension
    if not del_database_name.endswith(".db"):
        del_database_name += ".db"
    del_database_path = os.path.join("Databases", del_database_name)

    # Check if the database file exists
    if not os.path.exists(del_database_path):
        print(f"[HashDB] The database {del_database_name} does not exist.")
        return

    # Close any open connections to the database
    if del_database_path in db_connections:
        conn = db_connections[del_database_path]
        conn.close()
        del db_connections[del_database_path]

    db_size = os.path.getsize(del_database_path)

    double_check = input(f"[!] This database is {db_size} bytes. Are you sure you want to delete it? [Y/N]: ")
    if double_check.lower() == "y":
        try:
            os.remove(del_database_path)
            print(f"[*] Database {del_database_name} deleted successfully.")
        except Exception as e:
            print(f"[!] Error deleting the database: {e}")
    else:
        print(f"[*] Deletion of {del_database_name} cancelled.")

def create_hash_table(hash_db, hash_type):
    conn = sqlite3.connect(hash_db)
    db_connections[hash_db] = conn
    cursor = conn.cursor()
    cursor.execute(f'''CREATE TABLE IF NOT EXISTS {hash_type}hashes (
                        id INTEGER PRIMARY KEY, 
                        hash TEXT UNIQUE)''')
    cursor.execute(f'''CREATE INDEX IF NOT EXISTS idx_hash ON {hash_type}hashes(hash)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS KnownHashes (
                        id INTEGER PRIMARY KEY, 
                        hash TEXT UNIQUE,
                        password TEXT,
                        hash_type TEXT)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_known_hash ON KnownHashes(hash)''')
    conn.commit()
    print(f"[+] Created database for {hash_type.upper()} hashes and known hashes ({os.path.abspath(hash_db)})")
    print(f"[!] Note: This database will only work with the selected hash type -> {hash_type.upper()}")
    print(f"[!] Note: HashDB only supports single hash type databases, so for multiple types please create multiple databases.")

def create_password_table(password_db):
    conn = sqlite3.connect(password_db)
    db_connections[password_db] = conn
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS PlainTextPasswords (
                        id INTEGER PRIMARY KEY, 
                        password TEXT UNIQUE)''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS idx_password ON PlainTextPasswords(password)''')
    conn.commit()
    print(f"[+] Created database for plain text passwords ({os.path.abspath(password_db)})")

def create_database(database_name, database_type, database_hash_type):
    database_name = database_name + ".db"
    db_path = os.path.join("Databases", database_name)
    if database_type == "-h":
        create_hash_table(db_path, database_hash_type)
    elif database_type == "-w":
        create_password_table(db_path)
    else:
        print("Invalid database type. Use '-h' for hash list or '-w' for word list.")

def load_passwords(password_list_path, target_db, table_name):
    # Ensure the target_db has the .db extension
    if not target_db.endswith(".db"):
        target_db += ".db"

    target_db_path = os.path.join("Databases", target_db)
    batch_size = 1000  # Adjust batch size based on memory and performance

    # Count the number of lines in the password file
    with open(password_list_path, 'r', encoding='utf-8', errors='ignore') as file:
        total_lines = sum(1 for line in file)

    with sqlite3.connect(target_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}';")
        table_exists = cursor.fetchone()
        if table_exists:
            start_time = time.time()
            with open(password_list_path, 'r', encoding='utf-8', errors='ignore') as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                batch = []
                with conn:  # Use transaction to optimize writes
                    for line in tqdm(iter(mmapped_file.readline, b""), total=total_lines, unit='lines', desc='Loading passwords'):
                        password = line.decode('utf-8', errors='ignore').strip()
                        batch.append((password,))
                        if len(batch) >= batch_size:
                            cursor.executemany(f"INSERT OR IGNORE INTO {table_name} (password) VALUES (?)", batch)
                            conn.commit()
                            batch.clear()
                    if batch:
                        cursor.executemany(f"INSERT OR IGNORE INTO {table_name} (password) VALUES (?)", batch)
                        conn.commit()
            elapsed_time = time.time() - start_time
            print(f"[+] Loaded {password_list_path} into {table_name} in {elapsed_time:.2f} seconds.")
        else:
            print(f"[!] Table {table_name} does not exist in {os.path.abspath(target_db_path)}")

def load_hashes(hash_list_path, target_db, table_name):
    # Ensure the target_db has the .db extension
    if not target_db.endswith(".db"):
        target_db += ".db"

    target_db_path = os.path.join("Databases", target_db)
    batch_size = 10000  # Adjust batch size based on memory and performance

    with sqlite3.connect(target_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}';")
        table_exists = cursor.fetchone()
        if table_exists:
            with open(hash_list_path, 'r') as file:
                batch = []
                for line in file:
                    hash_value = line.strip()
                    batch.append((hash_value,))
                    if len(batch) >= batch_size:
                        cursor.executemany(f"INSERT OR IGNORE INTO {table_name} (hash) VALUES (?)", batch)
                        batch.clear()
                if batch:
                    cursor.executemany(f"INSERT OR IGNORE INTO {table_name} (hash) VALUES (?)", batch)
            conn.commit()
            print(f"[+] Loaded {hash_list_path} into {table_name}.")
        else:
            print(f"[!] Table {table_name} does not exist in {os.path.abspath(target_db_path)}")

def main():
    # Dictionary to keep track of open connections

    # Check for Databases folder and create it if it doesn't exist
    if not os.path.exists('Databases'):
        os.makedirs('Databases')

    clear_terminal()
    print("""

██╗  ██╗ █████╗ ███████╗██╗  ██╗██████╗ ██████╗ 
██║  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██╔══██╗
███████║███████║███████╗███████║██║  ██║██████╔╝
██╔══██║██╔══██║╚════██║██╔══██║██║  ██║██╔══██╗
██║  ██║██║  ██║███████║██║  ██║██████╔╝██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝ 
    """)

    print("[!] Cause chaos.")
    print("[!] By default attempts to use 50% of available memory for cracking. (Change with set mem [percentage] -> 'set mem 70' )")
    print("")
    print("Use 'help' for... help.")

    password_db = ''
    hash_db = ''
    password_list_path = ""
    hash_list_path = ""
    hash_type = ""
    verbose = False

    while True:
        print("")
        choice = input("[HashDB] > ")

        if choice.startswith("create") or choice.startswith("-c"):
            parts = choice.split(" ")
            if len(parts) >= 3:
                database_type = parts[1]
                database_name = parts[2]
                database_hash_type = parts[3] if len(parts) > 3 and database_type == "-h" else ""
                if database_type in ["-h", "-w"]:
                    create_database(database_name, database_type, database_hash_type)
                else:
                    print("Invalid usage detected ->\n Correct usage: [create [-w/-h (wordlist or hash list)] [databaseName] [hash_type (leave blank if using -w)]]")
            else:
                print("Invalid usage detected ->\n Correct usage: [create [-w/-h (wordlist or hash list)] [databaseName] [hash_type (leave blank if using -w)]]")
        elif choice.startswith("delete") or choice.startswith("-d"):
            del_database_name = choice.split(" ")[1]
            delete_table(del_database_name)
        elif choice.startswith("start") or choice.startswith("-s"):
            parts = choice.split(" ")
            if len(parts) == 4:
                password_db = parts[1]
                password_table = "PlainTextPasswords"
                hash_db = parts[2]
                hash_type = parts[3]
                # Ensure the database names have the .db extension
                if not password_db.endswith(".db"):
                    password_db += ".db"
                if not hash_db.endswith(".db"):
                    hash_db += ".db"
                password_db_path = os.path.join("Databases", password_db)
                hash_db_path = os.path.join("Databases", hash_db)
                crack_hashes(password_db_path, hash_db_path, hash_type, password_table, verbose)
            else:
                print("\n[!] Correct usage: start [passwordListDatabase] [passwordTableName] [targetHashDatabase] [hashTableName] [hashType]")
        elif choice.startswith("set -t") or choice.startswith("set type"):
            hash_type_desired = choice.split(" ")[2]
            hash_type = select_hash_type(hash_type_desired)
        elif choice.startswith("load -h") or choice.startswith("load hashlist"):
            parts = choice.split(" ")
            if len(parts) == 5:
                hash_list_path = parts[2]
                target_db = parts[3]
                hash_type = parts[4]
                table_name = hash_type + "hashes"
                hash_list_path = select_file(hash_list_path)
                load_hashes(hash_list_path, target_db, table_name)
            else:
                print("\n[!] Correct usage: load hashlist <file_path> <targetDB> <tableName>")
        elif choice.startswith("load -w") or choice.startswith("load wordlist"):
            parts = choice.split(" ")
            if len(parts) == 5:
                password_list_path = parts[2]
                target_db = parts[3]
                table_name = "PlainTextPasswords"
                password_list_path = select_file(password_list_path)
                load_passwords(password_list_path, target_db, table_name)
            else:
                print("\n[!] Correct usage: load wordlist <file_path> <targetDB> <tableName>")
        elif choice.startswith("set verbose") or choice.startswith("set -v"):
            verboseOption = choice.split(" ")[2]
            verbose = verboseOption.lower() == "on"
        elif choice.startswith('exit') or choice.startswith('-e'):
            break
        elif choice.startswith("help") or choice.startswith("-h"):
            display_help_menu()
        else:
            print("Invalid choice. Please enter a valid option.")

db_connections = {}

if __name__ == "__main__":
    main()
