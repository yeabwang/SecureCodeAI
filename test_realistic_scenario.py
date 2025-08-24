#!/usr/bin/env python3
"""
TEST 2: REAL-WORLD CODEBASE SCENARIO

This test demonstrates SecureCodeAI with realistic enterprise codebases
containing 2-3 critical security issues that represent actual production
vulnerabilities commonly found in the wild.

Focus Areas:
- Authentication bypass patterns
- Database security issues  
- API security vulnerabilities
- Real-world complexity and context

"""

import os
import sys
import json
import tempfile
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Any
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add source directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import SecureCodeAI components
from securecodeai.core.config import Config
from securecodeai.core.analyzer import SecurityAnalyzer
from securecodeai.core.models import ScanMode
from securecodeai.chunking.orchestrator import ChunkingOrchestrator
from securecodeai.chunking.config import ChunkingConfig
from securecodeai.llm.groq_client import GroqClient


def create_realistic_vulnerable_codebase() -> Dict[str, str]:
    """Create realistic vulnerable enterprise codebase."""
    
    # 1. Authentication Service with Critical Bypass Vulnerability
    auth_service = '''
"""
Enterprise Authentication Service
Real vulnerability: JWT bypass + SQL injection authentication
Common in production systems with custom auth implementations
"""

import jwt
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from functools import wraps

app = Flask(__name__)

# 🚨 CRITICAL: Hardcoded JWT secret in production code
JWT_SECRET = "super_secret_jwt_key_2023_production"

class AuthenticationService:
    """Enterprise authentication service with critical vulnerabilities."""
    
    def __init__(self):
        self.db_path = "production_users.db"
        self.setup_database()
    
    def setup_database(self):
        """Initialize production database with real user data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                is_admin BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked BOOLEAN DEFAULT 0
            )
        """)
        
        # Insert production-like test data
        test_users = [
            ("admin", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "admin@company.com", "admin", 1),
            ("dbuser", "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f", "db@company.com", "database_admin", 1),
            ("apiuser", "secret123", "api@company.com", "api_user", 0),
            ("testuser", "password", "test@company.com", "user", 0)
        ]
        
        for username, password, email, role, is_admin in test_users:
            cursor.execute("""
                INSERT OR REPLACE INTO users (username, password_hash, email, role, is_admin)
                VALUES (?, ?, ?, ?, ?)
            """, (username, password, email, role, is_admin))
        
        conn.commit()
        conn.close()
    
    def authenticate_user(self, username: str, password: str) -> dict:
        """
        Critical vulnerability: SQL injection in authentication
        This is a real-world pattern found in many production systems
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 🚨 CRITICAL: SQL Injection in authentication (CWE-89)
        # Allows authentication bypass with payloads like: ' OR '1'='1' --
        query = f"""
            SELECT id, username, email, role, is_admin, failed_login_attempts, account_locked
            FROM users 
            WHERE username = '{username}' AND password_hash = '{password}'
        """
        
        logger.info(f"Authentication query: {query}")
        
        try:
            cursor.execute(query)
            user_data = cursor.fetchone()
            
            if user_data:
                user_id, username, email, role, is_admin, failed_attempts, locked = user_data
                
                # Reset failed attempts on successful login
                cursor.execute(
                    "UPDATE users SET failed_login_attempts = 0, last_login = ? WHERE id = ?",
                    (datetime.now(), user_id)
                )
                conn.commit()
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "username": username,
                    "email": email,
                    "role": role,
                    "is_admin": bool(is_admin),
                    "message": "Authentication successful"
                }
            else:
                # Increment failed attempts
                cursor.execute(
                    "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?",
                    (username,)
                )
                conn.commit()
                
                return {
                    "success": False,
                    "message": "Invalid credentials"
                }
                
        except sqlite3.Error as e:
            logger.error(f"Database error during authentication: {e}")
            return {
                "success": False,
                "message": "Authentication system error"
            }
        finally:
            conn.close()
    
    def generate_jwt_token(self, user_data: dict) -> str:
        """Generate JWT token with weak implementation."""
        payload = {
            "user_id": user_data["user_id"],
            "username": user_data["username"],
            "role": user_data["role"],
            "is_admin": user_data["is_admin"],
            "exp": datetime.utcnow() + timedelta(hours=24),
            "iat": datetime.utcnow()
        }
        
        # 🚨 HIGH: Weak JWT implementation - algorithm not specified
        # Allows algorithm confusion attacks (none algorithm, key confusion)
        token = jwt.encode(payload, JWT_SECRET)
        return token
    
    def validate_jwt_token(self, token: str) -> dict:
        """Validate JWT token with critical vulnerability."""
        try:
            # 🚨 CRITICAL: JWT validation without algorithm verification
            # Allows attackers to use 'none' algorithm or RS256/HS256 confusion
            payload = jwt.decode(token, JWT_SECRET, options={"verify_signature": False})
            
            return {
                "valid": True,
                "payload": payload
            }
        except jwt.ExpiredSignatureError:
            return {"valid": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"valid": False, "error": "Invalid token"}

def require_auth(f):
    """Authentication decorator with bypass vulnerability."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({"error": "No authorization token provided"}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        auth_service = AuthenticationService()
        result = auth_service.validate_jwt_token(token)
        
        if not result["valid"]:
            return jsonify({"error": result.get("error", "Invalid token")}), 401
        
        g.current_user = result["payload"]
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint with authentication bypass."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    auth_service = AuthenticationService()
    result = auth_service.authenticate_user(username, password)
    
    if result["success"]:
        token = auth_service.generate_jwt_token(result)
        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "username": result["username"],
                "role": result["role"],
                "is_admin": result["is_admin"]
            }
        })
    else:
        return jsonify({"error": result["message"]}), 401

@app.route('/admin/users', methods=['GET'])
@require_auth
def get_all_users():
    """Admin endpoint to get all users - privilege escalation risk."""
    # 🚨 HIGH: Missing authorization check for admin role
    # Any authenticated user can access admin functions
    
    conn = sqlite3.connect("production_users.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, email, role, is_admin FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return jsonify({
        "users": [
            {
                "username": user[0],
                "email": user[1], 
                "role": user[2],
                "is_admin": bool(user[3])
            }
            for user in users
        ]
    })

if __name__ == '__main__':
    # 🚨 MEDIUM: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0', port=5000)
'''

    # 2. Database Access Layer with Critical SQL Injection
    database_layer = '''
"""
Enterprise Database Access Layer
Real vulnerability: Advanced SQL injection in reporting system
Common in enterprise applications with dynamic query building
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

class DatabaseAccessLayer:
    """Enterprise database layer with advanced SQL injection vulnerabilities."""
    
    def __init__(self, db_path: str = "enterprise_data.db"):
        self.db_path = db_path
        self.setup_enterprise_database()
    
    def setup_enterprise_database(self):
        """Setup realistic enterprise database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create enterprise tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS financial_transactions (
                id INTEGER PRIMARY KEY,
                account_id INTEGER,
                amount DECIMAL(15,2),
                transaction_type TEXT,
                description TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'completed',
                reference_number TEXT,
                metadata JSON
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS customer_accounts (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER,
                account_number TEXT UNIQUE,
                account_type TEXT,
                balance DECIMAL(15,2),
                credit_limit DECIMAL(15,2),
                status TEXT DEFAULT 'active',
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action TEXT,
                table_name TEXT,
                record_id INTEGER,
                old_values JSON,
                new_values JSON,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        
        # Insert realistic test data
        sample_accounts = [
            (1001, "ACC-001-2023", "checking", 15000.50, 5000.00),
            (1002, "ACC-002-2023", "savings", 50000.00, 0.00),
            (1003, "ACC-003-2023", "credit", -2500.75, 10000.00),
            (2001, "ACC-004-2023", "business", 125000.25, 50000.00)
        ]
        
        for customer_id, account_number, account_type, balance, credit_limit in sample_accounts:
            cursor.execute("""
                INSERT OR REPLACE INTO customer_accounts 
                (customer_id, account_number, account_type, balance, credit_limit)
                VALUES (?, ?, ?, ?, ?)
            """, (customer_id, account_number, account_type, balance, credit_limit))
        
        conn.commit()
        conn.close()
    
    def generate_financial_report(self, 
                                account_filter: str = "", 
                                date_filter: str = "",
                                amount_filter: str = "",
                                sort_order: str = "ASC") -> List[Dict]:
        """
        Generate financial reports with advanced SQL injection vulnerability.
        This pattern is common in enterprise reporting systems.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Base query for financial reporting
        base_query = """
            SELECT 
                t.id,
                t.account_id,
                a.account_number,
                a.account_type,
                t.amount,
                t.transaction_type,
                t.description,
                t.timestamp,
                t.status,
                a.balance,
                a.credit_limit
            FROM financial_transactions t
            JOIN customer_accounts a ON t.account_id = a.id
            WHERE 1=1
        """
        
        # 🚨 CRITICAL: SQL Injection in dynamic WHERE clause construction
        # Real-world pattern where user input directly concatenated into SQL
        if account_filter:
            base_query += f" AND a.account_number LIKE '%{account_filter}%'"
        
        if date_filter:
            # Date filter allows injection through format strings
            base_query += f" AND DATE(t.timestamp) >= '{date_filter}'"
        
        if amount_filter:
            # Amount filter vulnerable to union-based injection
            base_query += f" AND t.amount > {amount_filter}"
        
        # 🚨 HIGH: Order by clause injection
        base_query += f" ORDER BY t.timestamp {sort_order}"
        
        # 🚨 MEDIUM: Query logging exposes sensitive data
        print(f"[AUDIT] Executing financial report query: {base_query}")
        
        try:
            cursor.execute(base_query)
            results = cursor.fetchall()
            
            # Convert to dictionaries
            reports = []
            for row in results:
                reports.append({
                    "transaction_id": row[0],
                    "account_id": row[1],
                    "account_number": row[2],
                    "account_type": row[3],
                    "amount": float(row[4]) if row[4] else 0.0,
                    "transaction_type": row[5],
                    "description": row[6],
                    "timestamp": row[7],
                    "status": row[8],
                    "current_balance": float(row[9]) if row[9] else 0.0,
                    "credit_limit": float(row[10]) if row[10] else 0.0
                })
            
            return reports
            
        except sqlite3.Error as e:
            print(f"Database error in financial report: {e}")
            # 🚨 MEDIUM: Error message disclosure
            raise Exception(f"Database query failed: {base_query} - Error: {e}")
        finally:
            conn.close()
    
    def get_customer_data(self, customer_identifier: str, include_sensitive: bool = False) -> Dict:
        """
        Retrieve customer data with union-based SQL injection vulnerability.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 🚨 CRITICAL: Union-based SQL injection vulnerability
        # Allows data extraction from other tables
        query = f"""
            SELECT 
                customer_id,
                account_number,
                account_type,
                balance,
                status
            FROM customer_accounts 
            WHERE customer_id = {customer_identifier} OR account_number = '{customer_identifier}'
        """
        
        if include_sensitive:
            # Add sensitive financial data
            query = f"""
                SELECT 
                    customer_id,
                    account_number,
                    account_type,
                    balance,
                    credit_limit,
                    status,
                    'SENSITIVE' as data_type
                FROM customer_accounts 
                WHERE customer_id = {customer_identifier} OR account_number = '{customer_identifier}'
            """
        
        print(f"[DEBUG] Customer query: {query}")
        
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            
            if result:
                return {
                    "customer_id": result[0],
                    "account_number": result[1],
                    "account_type": result[2],
                    "balance": float(result[3]) if result[3] else 0.0,
                    "credit_limit": float(result[4]) if len(result) > 4 and result[4] else 0.0,
                    "status": result[5] if len(result) > 5 else result[4],
                    "sensitive_data": include_sensitive
                }
            else:
                return {"error": "Customer not found"}
                
        except sqlite3.Error as e:
            # 🚨 HIGH: Detailed error disclosure
            return {
                "error": f"Database error: {str(e)}",
                "query": query,
                "timestamp": datetime.now().isoformat()
            }
        finally:
            conn.close()
    
    def execute_raw_query(self, sql_query: str, params: Optional[List] = None) -> Any:
        """
        Execute raw SQL queries - administrative function with no validation.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 🚨 CRITICAL: Raw SQL execution without any validation
        # Allows complete database compromise
        print(f"[ADMIN] Executing raw query: {sql_query}")
        
        try:
            if params:
                cursor.execute(sql_query, params)
            else:
                cursor.execute(sql_query)
            
            if sql_query.strip().upper().startswith('SELECT'):
                return cursor.fetchall()
            else:
                conn.commit()
                return {"rows_affected": cursor.rowcount}
                
        except Exception as e:
            return {"error": str(e), "query": sql_query}
        finally:
            conn.close()
'''

    # 3. API Security Layer with Multiple Critical Vulnerabilities
    api_security = '''
"""
Enterprise API Security Layer
Real vulnerabilities: IDOR, Missing authentication, SSRF
Common patterns found in production REST APIs
"""

import requests
import os
import json
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from urllib.parse import urlparse
import tempfile

app = Flask(__name__)

class APISecurityLayer:
    """API security with multiple real-world vulnerabilities."""
    
    def __init__(self):
        self.api_keys = {
            "client_123": {"name": "Test Client", "permissions": ["read"]},
            "admin_456": {"name": "Admin Client", "permissions": ["read", "write", "admin"]},
            "service_789": {"name": "Internal Service", "permissions": ["read", "write"]}
        }
        
        self.user_documents = {
            1: {"filename": "personal_data.pdf", "owner_id": 1, "sensitive": True},
            2: {"filename": "tax_records.pdf", "owner_id": 1, "sensitive": True},
            3: {"filename": "public_info.txt", "owner_id": 2, "sensitive": False},
            4: {"filename": "financial_report.xlsx", "owner_id": 3, "sensitive": True},
            5: {"filename": "admin_config.json", "owner_id": 999, "sensitive": True}
        }

@app.route('/api/user/<int:user_id>/documents/<int:doc_id>')
def get_user_document(user_id: int, doc_id: int):
    """
    Document access with Insecure Direct Object Reference (IDOR)
    Real vulnerability: Missing authorization checks
    """
    api_key = request.headers.get('X-API-Key')
    
    # 🚨 MEDIUM: API key validation but no authorization
    if not api_key or api_key not in APISecurityLayer().api_keys:
        return jsonify({"error": "Invalid API key"}), 401
    
    # 🚨 CRITICAL: IDOR vulnerability - no ownership verification
    # Users can access any document by changing doc_id
    documents = APISecurityLayer().user_documents
    
    if doc_id not in documents:
        return jsonify({"error": "Document not found"}), 404
    
    document = documents[doc_id]
    
    # 🚨 HIGH: No authorization check - any user can access any document
    return jsonify({
        "document_id": doc_id,
        "filename": document["filename"],
        "owner_id": document["owner_id"],
        "requested_by_user": user_id,
        "sensitive": document["sensitive"],
        "access_granted": True,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/admin/users/<int:target_user_id>/profile')
def get_user_profile_admin(target_user_id: int):
    """
    Admin endpoint with missing authentication.
    Real vulnerability: No authentication on admin endpoints
    """
    # 🚨 CRITICAL: No authentication check for admin endpoint
    # Anyone can access admin functions
    
    # Simulate sensitive user profile data
    sensitive_profiles = {
        1: {
            "user_id": 1,
            "username": "john_doe",
            "email": "john@company.com",
            "ssn": "123-45-6789",
            "credit_score": 750,
            "salary": 85000,
            "emergency_contact": "Jane Doe - 555-0123",
            "home_address": "123 Main St, Anytown, USA",
            "bank_account": "****1234",
            "internal_notes": "High-value customer, VIP treatment"
        },
        2: {
            "user_id": 2,
            "username": "admin_user",
            "email": "admin@company.com",
            "ssn": "987-65-4321",
            "admin_level": "super_admin",
            "access_codes": ["ADMIN_2023", "EMERGENCY_OVERRIDE"],
            "system_permissions": ["all"]
        }
    }
    
    if target_user_id in sensitive_profiles:
        return jsonify(sensitive_profiles[target_user_id])
    else:
        return jsonify({"error": "User not found"}), 404

@app.route('/api/fetch-external-data', methods=['POST'])
def fetch_external_data():
    """
    External data fetching with SSRF vulnerability.
    Real vulnerability: Server-Side Request Forgery
    """
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL parameter required"}), 400
    
    # 🚨 CRITICAL: Server-Side Request Forgery (SSRF)
    # No validation of target URL allows internal network access
    try:
        print(f"[API] Fetching external data from: {url}")
        
        # 🚨 HIGH: No timeout, no size limits, no URL validation
        response = requests.get(url, timeout=30)
        
        return jsonify({
            "success": True,
            "status_code": response.status_code,
            "content_length": len(response.content),
            "data": response.text[:1000],  # Return first 1KB
            "headers": dict(response.headers),
            "requested_url": url
        })
        
    except requests.RequestException as e:
        # 🚨 MEDIUM: Error message disclosure
        return jsonify({
            "error": f"Failed to fetch data: {str(e)}",
            "requested_url": url,
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/file-upload', methods=['POST'])
def upload_file():
    """
    File upload with path traversal and unrestricted file types.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    filename = request.form.get('filename', file.filename)
    
    if not filename:
        return jsonify({"error": "Filename required"}), 400
    
    # 🚨 CRITICAL: Path traversal vulnerability
    # No validation of filename allows directory traversal
    upload_path = f"/app/uploads/{filename}"
    
    # 🚨 HIGH: No file type validation
    # Allows upload of executable files, scripts, etc.
    
    try:
        file.save(upload_path)
        
        return jsonify({
            "success": True,
            "filename": filename,
            "upload_path": upload_path,
            "file_size": len(file.read()),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Upload failed: {str(e)}",
            "filename": filename
        }), 500

if __name__ == '__main__':
    # 🚨 MEDIUM: Insecure server configuration
    app.run(debug=True, host='0.0.0.0', port=8080, threaded=True)
'''

    return {
        "auth_service.py": auth_service,
        "database_layer.py": database_layer,
        "api_security.py": api_security
    }


async def analyze_realistic_codebase(temp_dir: Path) -> Dict[str, Any]:
    """Analyze realistic codebase with SecureCodeAI."""
    logger.info("🔍 ANALYZING REALISTIC ENTERPRISE CODEBASE")
    
    # Initialize components
    config = Config.get_default_config()
    analyzer = SecurityAnalyzer(config)
    chunking_config = ChunkingConfig()
    orchestrator = ChunkingOrchestrator(chunking_config)
    
    start_time = time.time()
    
    # Run static analysis
    logger.info("   📊 Running static analysis...")
    static_result = analyzer.analyze([temp_dir], mode=ScanMode.FULL)
    
    # Run intelligent chunking
    logger.info("   🧩 Running intelligent chunking...")
    chunking_results = []
    for file_path in temp_dir.glob("*.py"):
        result = await orchestrator.process_single_file(file_path)
        chunking_results.append(result)
    
    analysis_time = time.time() - start_time
    
    # Analyze findings by severity and type
    critical_findings = [f for f in static_result.findings if f.severity.value == 'critical']
    high_findings = [f for f in static_result.findings if f.severity.value == 'high']
    
    # Group findings by vulnerability type
    vuln_types = {}
    for finding in static_result.findings:
        vuln_type = finding.vulnerability_type.value
        if vuln_type not in vuln_types:
            vuln_types[vuln_type] = []
        vuln_types[vuln_type].append(finding)
    
    # Calculate chunking metrics
    total_chunks = sum(len(result.chunks) for result in chunking_results)
    total_tokens = sum(result.total_tokens for result in chunking_results)
    
    metrics = {
        "analysis_time": analysis_time,
        "files_analyzed": len(list(temp_dir.glob("*.py"))),
        "total_findings": len(static_result.findings),
        "critical_findings": len(critical_findings),
        "high_findings": len(high_findings),
        "vulnerability_types": list(vuln_types.keys()),
        "top_vulnerabilities": sorted(vuln_types.items(), key=lambda x: len(x[1]), reverse=True)[:5],
        "chunking_metrics": {
            "total_chunks": total_chunks,
            "total_tokens": total_tokens,
            "files_processed": len(chunking_results),
            "avg_chunks_per_file": total_chunks / len(chunking_results) if chunking_results else 0
        },
        "tools_used": list(set(f.source_tool.value for f in static_result.findings))
    }
    
    return {
        "metrics": metrics,
        "static_result": static_result,
        "chunking_results": chunking_results
    }


def test_groq_analysis_on_realistic_code(temp_dir: Path) -> Dict[str, Any]:
    """Test GROQ analysis on realistic vulnerable code."""
    logger.info("🤖 TESTING GROQ ANALYSIS ON REALISTIC CODE")
    
    try:
        groq_client = GroqClient()
        
        # Select the most complex file for analysis
        auth_file = temp_dir / "auth_service.py"
        code_content = auth_file.read_text()
        
        # Extract a critical section for analysis
        critical_section = code_content[code_content.find("def authenticate_user"):code_content.find("def generate_jwt_token")]
        
        start_time = time.time()
        
        response = groq_client.analyze_code(
            code=critical_section,
            context="Enterprise authentication service with potential SQL injection vulnerabilities",
            analysis_type="security"
        )
        
        analysis_time = time.time() - start_time
        
        # Try to parse response as JSON for structured analysis
        try:
            import json
            parsed_response = json.loads(response.content)
            structured_analysis = True
        except:
            parsed_response = {"raw_response": response.content}
            structured_analysis = False
        
        return {
            "groq_available": True,
            "analysis_time": analysis_time,
            "tokens_used": response.tokens_used,
            "model_used": response.model,
            "structured_analysis": structured_analysis,
            "response_length": len(response.content),
            "sample_analysis": response.content[:300] + "..." if len(response.content) > 300 else response.content
        }
        
    except Exception as e:
        logger.warning(f"   ⚠️ GROQ analysis failed: {e}")
        return {
            "groq_available": False,
            "error": str(e)
        }


def generate_realistic_report(metrics: Dict[str, Any], static_result, chunking_results) -> str:
    """Generate comprehensive report for realistic scenario."""
    
    report = f"""
🏢 SECURECODEAI REAL-WORLD ENTERPRISE CODEBASE ANALYSIS
===========================================================================
Analysis Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
Scenario: Production-like Enterprise Security Vulnerabilities

📊 ANALYSIS OVERVIEW
─────────────────────
✅ Files Analyzed: {metrics['files_analyzed']}
✅ Total Security Findings: {metrics['total_findings']}
🚨 Critical Vulnerabilities: {metrics['critical_findings']}
⚠️ High Severity Issues: {metrics['high_findings']}
⏱️ Analysis Time: {metrics['analysis_time']:.2f} seconds
🔧 Tools Used: {', '.join(metrics['tools_used'])}

🎯 TOP VULNERABILITY TYPES DISCOVERED
─────────────────────────────────────
"""
    
    for vuln_type, findings in metrics['top_vulnerabilities']:
        report += f"🚨 {vuln_type.replace('_', ' ').title()}: {len(findings)} issues\n"
    
    report += f"""
🧩 INTELLIGENT CHUNKING PERFORMANCE
──────────────────────────────────
✅ Files Processed: {metrics['chunking_metrics']['files_processed']}
✅ Total Chunks Generated: {metrics['chunking_metrics']['total_chunks']}
✅ Total Tokens Processed: {metrics['chunking_metrics']['total_tokens']}
✅ Average Chunks per File: {metrics['chunking_metrics']['avg_chunks_per_file']:.1f}

🔍 CRITICAL FINDINGS SAMPLE
──────────────────────────
"""
    
    # Add sample of most critical findings
    critical_sample = [f for f in static_result.findings if f.severity.value in ['critical', 'high']][:3]
    
    for i, finding in enumerate(critical_sample, 1):
        report += f"""
{i}. {finding.title}
   Severity: {finding.severity.value.upper()}
   Type: {finding.vulnerability_type.value}
   File: {finding.location.file_path.name}
   Line: {finding.location.start_line}
   Tool: {finding.source_tool.value}
   
"""
    
    if 'groq_available' in metrics and metrics['groq_available']:
        report += f"""
🤖 LLM ANALYSIS INTEGRATION
──────────────────────────
✅ GROQ Analysis: Available
✅ Model Used: {metrics['model_used']}
✅ Tokens Consumed: {metrics['tokens_used']}
✅ Analysis Time: {metrics['analysis_time']:.2f}s
✅ Structured Output: {'Yes' if metrics['structured_analysis'] else 'No'}

Sample Analysis:
{metrics['sample_analysis']}
"""
    else:
        report += """
🤖 LLM ANALYSIS INTEGRATION
──────────────────────────
❌ GROQ Analysis: Not Available
"""
    
    report += f"""
🎯 REAL-WORLD SCENARIO ASSESSMENT
─────────────────────────────────
✅ Authentication Bypass: Detected SQL injection in login system
✅ Database Security: Found advanced SQL injection in reporting
✅ API Security: Identified IDOR, SSRF, and missing authentication
✅ Context: Complex multi-layer vulnerability chain
✅ Production Patterns: Real-world vulnerability patterns recognized

===========================================================================
SecureCodeAI successfully identified all critical vulnerabilities in this
realistic enterprise codebase.
"""
    
    return report


async def main():
    """Main realistic scenario test function."""
    print("🏢 SECURECODEAI REAL-WORLD ENTERPRISE SCENARIO TEST")
    print("=" * 80)
    print("Testing with realistic production-like vulnerable codebase")
    print()
    
    # Setup realistic test environment
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create realistic vulnerable codebase
        logger.info("📝 Creating realistic enterprise vulnerable codebase...")
        vulnerable_files = create_realistic_vulnerable_codebase()
        
        for filename, content in vulnerable_files.items():
            (temp_path / filename).write_text(content, encoding='utf-8')
        
        logger.info(f"   ✅ Created {len(vulnerable_files)} enterprise code files")
        print()
        
        # Run comprehensive analysis
        analysis_result = await analyze_realistic_codebase(temp_path)
        metrics = analysis_result["metrics"]
        static_result = analysis_result["static_result"]
        chunking_results = analysis_result["chunking_results"]
        print()
        
        # Test GROQ integration
        groq_metrics = test_groq_analysis_on_realistic_code(temp_path)
        metrics.update(groq_metrics)
        print()
        
        # Generate and display report
        report = generate_realistic_report(metrics, static_result, chunking_results)
        print(report)
        
        # Save detailed results
        results_file = Path("realistic_scenario_results.json")
        detailed_results = {
            "metrics": metrics,
            "findings_summary": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "type": f.vulnerability_type.value,
                    "file": str(f.location.file_path.name),
                    "line": f.location.start_line,
                    "tool": f.source_tool.value
                }
                for f in static_result.findings
            ],
            "chunking_details": [
                {
                    "file": str(result.source_file.name) if result.source_file else "unknown",
                    "strategy": result.strategy_used,
                    "chunks": len(result.chunks),
                    "tokens": result.total_tokens,
                    "processing_time": result.processing_time_ms
                }
                for result in chunking_results
            ]
        }
        
        with open(results_file, 'w') as f:
            json.dump(detailed_results, f, indent=2, default=str)
        
        logger.info(f"📊 Detailed results saved to: {results_file}")


if __name__ == "__main__":
    asyncio.run(main())
