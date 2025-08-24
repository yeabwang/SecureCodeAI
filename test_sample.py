#!/usr/bin/env python3
"""
Test file with various security vulnerabilities for SecureCodeAI testing
"""

import subprocess
import hashlib
import sqlite3
import pickle
import logging

# Hardcoded credentials (CWE-798)
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

# SQL Injection vulnerability (CWE-89)
def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    
    conn.close()
    return result is not None

# Command Injection vulnerability (CWE-78)
def process_file(filename):
    # Dangerous use of subprocess with user input
    command = f"ls -la {filename}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# Weak cryptography (CWE-327)
def hash_password(password):
    # Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

# Unsafe deserialization (CWE-502)
def load_user_data(data):
    # Dangerous pickle deserialization
    return pickle.loads(data)

# Information disclosure (CWE-200)
def debug_info():
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    
    # Logging sensitive information
    logger.debug(f"Database password: {DATABASE_PASSWORD}")
    logger.debug(f"API key: {API_KEY}")

# Insecure random number generation (CWE-338)
import random
def generate_session_token():
    # Using weak random number generator
    return str(random.randint(100000, 999999))

if __name__ == "__main__":
    # Test the vulnerable functions
    print("Testing SecureCodeAI...")
    
    # SQL injection test
    result = authenticate_user("admin", "password")
    print(f"Authentication result: {result}")
    
    # Command injection test
    output = process_file("../../../etc/passwd")
    print(f"File processing result: {output}")
    
    # Weak crypto test
    hashed = hash_password("mypassword")
    print(f"Hashed password: {hashed}")
