Blind SQL Injection Enumerator

• Overview

Advanced Blind SQL Injection Enumerator is a sophisticated Python-based penetration testing tool designed to detect and exploit various types of blind SQL injection vulnerabilities. Unlike traditional tools that focus on a single injection technique, this enumerator intelligently identifies and leverages multiple blind SQLi vectors including time-based, boolean-based, error-based, and union-based injections.

• Key Features

· Multi-Vector Detection: Automatically identifies exploitable blind SQL injection types
· Intelligent Technique Selection: Chooses the most efficient exploitation method based on target response
· Parallel Processing: Utilizes multi-threading for faster data extraction
· Comprehensive Enumeration: Full database schema discovery and data exfiltration
· Interactive Mode: User-friendly CLI with step-by-step enumeration workflow
· DVWA Integration: Specifically optimized for Damn Vulnerable Web Application (DVWA)

• Supported Injection Techniques

1. Time-Based Injection

· Uses SLEEP() or BENCHMARK() functions
· Measures response time differences
· Fallback method when other techniques fail

2. Boolean-Based Injection

· Leverages conditional responses
· Compares true/false response patterns
· Efficient for content-differential attacks

3. Error-Based Injection

· Utilizes EXTRACTVALUE() and UPDATEXML() functions
· Extracts data through error messages
· High-speed data exfiltration when supported

4. Union-Based Injection

· Direct data retrieval via UNION queries
· Automatic column count detection
· Fastest extraction method when available

• Installation

Prerequisites

· Python 3.7 or higher
· requests library

Installation Steps

```bash
# Clone or download the script
git clone [repository-url]
cd sql-injection-enumerator

# Install required dependencies
pip install requests

# Make script executable (Linux/Mac)
chmod +x dvwa_blind_advanced.py
```

• Usage

Basic Usage

```bash
python3 dvwa_blind_advanced.py -u http://target.com -s PHPSESSID
```

Complete Command Reference

```bash
python3 dvwa_blind_advanced.py \
  -u http://127.0.0.1:42001 \    # Target URL
  -s abcdef1234567890 \          # Session cookie value
  -l low \                       # Security level (low/medium/high)
  -t 20 \                        # Number of threads (default: 15)
  -d 1.5                         # Delay for time-based (default: 1.0)
```

Command Line Arguments

Argument Short Required Default Description
--url -u Yes - Target application URL
--session -s Yes - PHPSESSID cookie value
--level -l No low DVWA security level
--threads -t No 15 Concurrent threads
--delay -d No 1.0 Time-based delay (seconds)

• DVWA Configuration

Setup Instructions

1. Install DVWA following official documentation
2. Configure database and set security level to "Low"
3. Navigate to SQL Injection (Blind) section
4. Start the tool with appropriate parameters:

```bash
# Example for local DVWA installation
python3 dvwa_blind_advanced.py \
  -u http://localhost/dvwa \
  -s [your_session_id] \
  -l low
```

• Technical Implementation

Core Architecture

```python
BlindSQLiEnumerator
├── detect_injection_type()    # Auto-detection
├── test_condition()          # Conditional testing
├── extract_data()           # Data extraction
├── test_union_columns()     # UNION detection
└── interactive_mode()       # User interface
```

Extraction Methods

1. Binary Search: Logarithmic character discovery (O(log n))
2. Parallel Search: Concurrent ASCII range testing
3. Hybrid Approach: Adaptive method switching based on performance
4. Union Extraction: Direct data retrieval when possible

Optimization Features

· Adaptive Thread Management: Dynamic thread allocation
· Response Caching: Reduced redundant requests
· Intelligent Fallback: Automatic technique switching
· Progress Tracking: Real-time extraction status

• Enumeration Workflow

Phase 1: Detection & Assessment

```
1. Establish baseline responses
2. Test various injection payloads
3. Identify working technique
4. Determine optimal extraction method
```

Phase 2: Information Gathering

```
1. Database version and metadata
2. Current user and privileges
3. Available databases
4. Schema enumeration
```

Phase 3: Data Exfiltration

```
1. Table enumeration
2. Column discovery
3. Sample data retrieval
4. Complete data dumping
```

• Example Output

```plaintext
ADVANCED BLIND SQL INJECTION ENUMERATOR
============================================

[*] Detecting blind SQL injection type...
  Testing time-based...
  Testing boolean-based...
  Testing error-based...
[+] BOOLEAN-based injection detected!

[*] Using BOOLEAN-based technique

[*] DATABASE ENUMERATION
============================================
[*] Extracting bulk info...
[+] Database Version: 10.4.17-MariaDB
[+] Current Database: dvwa
[+] Current User: root@localhost
[+] Hostname: localhost

[*] Extracting all databases...
[+] Found 5 databases

DATABASES:
  1. dvwa
  2. information_schema
  3. mysql
  4. performance_schema
  5. test
```

• Security Considerations

Ethical Usage

• This tool is for authorized penetration testing and educational purposes only.

Legal Compliance

· Obtain proper authorization before testing
· Respect target system terms of service
· Comply with applicable laws and regulations
· Use only in controlled lab environments

Responsible Disclosure

If vulnerabilities are discovered:

1. Document findings thoroughly
2. Report to appropriate parties
3. Allow reasonable remediation time
4. Avoid public disclosure of sensitive data

• Testing Methodology

Pre-Engagement

1. Authorization: Obtain written permission
2. Scope Definition: Clearly define test boundaries
3. Backup Creation: Ensure system recoverability
4. Monitoring Setup: Establish activity logging

During Engagement

1. Progressive Testing: Start with non-destructive techniques
2. Impact Assessment: Evaluate system response
3. Data Handling: Securely store extracted information
4. Communication: Maintain stakeholder updates

Post-Engagement

1. Cleanup: Remove any test artifacts
2. Reporting: Provide detailed findings
3. Remediation: Suggest security improvements
4. Verification: Confirm vulnerability closure

• Troubleshooting

Common Issues

Issue Solution
Connection refused Verify target URL and port
Invalid session Update PHPSESSID cookie
No injection detected Check security level
Slow extraction Adjust thread count and delay
Encoding problems Ensure proper character handling

Debug Mode

Enable verbose output by modifying the script:

```python
# Add debug parameter
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
```

• Advanced Usage

Custom Payload Development

```python
# Extend the tool with custom payloads
custom_tests = [
    ("technique", "true_payload", "false_payload"),
    # Add your payloads here
]
```

Integration with Other Tools

```python
# Example: Integrate with existing frameworks
def export_results(format='json'):
    """Export enumeration results"""
    # Implementation for reporting
    pass
```

Performance Tuning

· Thread Optimization: Adjust based on network latency
· Timeout Configuration: Modify based on target response
· Batch Processing: Group similar queries
· Cache Management: Implement response caching

• Contributing

Development Guidelines

1. Fork the repository
2. Create feature branches
3. Maintain code style consistency
4. Add comprehensive testing
5. Update documentation

Code Standards

· Follow PEP 8 conventions
· Add type hints where applicable
· Include docstrings for functions
· Maintain backward compatibility

Testing Requirements

· Unit tests for core functions
· Integration tests for workflows
· Performance benchmarks
· Security validation

• License

This project is licensed for educational and authorized security testing purposes. Users are responsible for ensuring proper authorization before use.

• Support

Resources

· OWASP SQL Injection Guide
· DVWA Documentation
· SQL Injection Cheat Sheet

Reporting Issues

For bugs, feature requests, or security concerns:

1. Check existing issues
2. Provide detailed reproduction steps
3. Include environment information
4. Share relevant logs/output

• Learning Resources

Recommended Reading

1. "The Web Application Hacker's Handbook" by Dafydd Stuttard
2. OWASP Testing Guide
3. SQL Injection Attacks and Defense by Justin Clarke
4. PortSwigger Web Security Academy

Training Environments

· DVWA (Damn Vulnerable Web Application)
· WebGoat (OWASP training platform)
· bWAPP (Buggy Web Application)
· SQLi Labs (Specialized training)

---

Disclaimer: This tool is intended for legal security assessment purposes only. The developers assume no liability for unauthorized or malicious use. Always ensure you have explicit permission before testing any system.