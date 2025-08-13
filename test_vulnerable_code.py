#!/usr/bin/env python3
"""
Test file with intentional security vulnerabilities for testing SecureCodeAI
"""

import os
import subprocess
import pickle
import hashlib

# Vulnerability 1: Hardcoded password
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def authenticate_user(username, password):
    """Authenticate user with hardcoded credentials"""
    # Vulnerability 2: Hardcoded credentials comparison
    if username == "admin" and password == PASSWORD:
        return True
    return False

def execute_command(user_input):
    """Execute system command based on user input"""
    # Vulnerability 3: Command injection
    command = f"ls {user_input}"
    return subprocess.call(command, shell=True)

def load_user_data(data_file):
    """Load user data from pickle file"""
    # Vulnerability 4: Unsafe deserialization
    with open(data_file, 'rb') as f:
        return pickle.load(f)

def generate_hash(data):
    """Generate hash using weak algorithm"""
    # Vulnerability 5: Weak cryptographic hash
    return hashlib.md5(data.encode()).hexdigest()

def sql_query(user_id):
    """Execute SQL query with user input"""
    # Vulnerability 6: SQL injection potential
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def create_temp_file():
    """Create temporary file with predictable name"""
    # Vulnerability 7: Insecure temp file creation
    temp_file = "/tmp/data.txt"
    with open(temp_file, 'w') as f:
        f.write("sensitive data")
    return temp_file

class UserManager:
    def __init__(self):
        # Vulnerability 8: Debug mode enabled
        self.debug = True
        self.secret_key = "supersecret"
    
    def get_user_info(self, user_input):
        """Get user information"""
        # Vulnerability 9: Potential path traversal
        file_path = f"/data/users/{user_input}.json"
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except Exception as e:
            if self.debug:
                # Vulnerability 10: Information disclosure in debug mode
                print(f"Error: {e}")
                print(f"Secret key: {self.secret_key}")
            return None

if __name__ == "__main__":
    # Test the vulnerable functions
    print("Testing vulnerable code...")
    
    # Test authentication
    result = authenticate_user("admin", "admin123")
    print(f"Authentication result: {result}")
    
    # Test command execution
    execute_command("../")
    
    # Test hash generation
    hash_value = generate_hash("password123")
    print(f"Hash: {hash_value}")
    
    # Test user manager
    manager = UserManager()
    user_info = manager.get_user_info("../../../etc/passwd")
    
    print("Vulnerable code execution completed.")
