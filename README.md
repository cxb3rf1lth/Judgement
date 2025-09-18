# Judgement - Ultimate Security Testing Framework

Professional Penetration Testing Automation with Intelligent Chaining

## 🚀 Overview

Judgement is a comprehensive penetration testing automation framework designed for professional security assessments. It features intelligent chaining of multiple attack vectors, automated vulnerability discovery, and professional reporting capabilities.

## ✨ Key Features

- **🎯 Intelligent Target Discovery**: Automated discovery and analysis of attack surfaces
- **🔍 Parameter Discovery**: Advanced parameter mining and analysis
- **📁 Directory Fuzzing**: Comprehensive web directory and file discovery
- **⚡ Parameter Fuzzing**: Multi-payload vulnerability testing across 12+ attack vectors
- **🔓 Brute Force Testing**: Intelligent login form detection and credential testing  
- **🧠 Full Intelligent Assessment**: Orchestrated multi-phase security assessment
- **📊 Professional Reporting**: HTML and JSON reports with vulnerability details
- **🗄️ Database Storage**: SQLite backend for persistent finding storage
- **🎨 Rich CLI Interface**: Professional terminal UI with progress tracking
- **⚙️ Configurable Depth**: Quick, normal, deep, and thorough scan modes
- **🚀 Multi-threaded**: High-performance concurrent operations

## 🛠️ Installation

### Prerequisites
- Python 3.6+
- pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/cxb3rf1lth/Judgement.git
cd Judgement

# Install dependencies
pip install -r requirements.txt

# Run Judgement
python3 Judgement.py
```

## 🎯 Core Components

### 1. **JudgementOrchestrator**
Main orchestration engine that chains all security testing phases intelligently.

### 2. **IntelligentTargetDiscovery** 
Discovers additional targets through:
- Link extraction and analysis
- Subdomain enumeration
- Related asset identification

### 3. **IntelligentParameterDiscovery**
Identifies parameters through:
- URL query analysis
- Form field extraction
- Common parameter fuzzing
- Method-specific parameter discovery

### 4. **AdvancedFuzzer**
Multi-mode fuzzing engine supporting:
- Directory and file discovery
- Parameter-based vulnerability testing
- Extension-based enumeration
- Status code analysis

### 5. **PayloadGenerator**
Advanced payload system with 896+ payloads across 12 categories:
- SQL Injection (75 payloads)
- Cross-Site Scripting (101 payloads) 
- Command Injection (149 payloads)
- Server-Side Template Injection (49 payloads)
- Path Traversal (58 payloads)
- XML External Entity (42 payloads)
- Server-Side Request Forgery (94 payloads)
- LDAP Injection (30 payloads)
- NoSQL Injection (23 payloads)
- XPath Injection (62 payloads)
- CRLF Injection (52 payloads)
- HTTP Header Injection (61 payloads)

### 6. **DeepBruteForcer**
Intelligent brute force engine with:
- Login form detection
- Credential wordlist management
- Rate limiting and evasion
- Success pattern recognition

### 7. **ReportGenerator**
Professional reporting system generating:
- Comprehensive HTML reports with styling
- JSON exports for automation integration
- Vulnerability severity classification
- Evidence and payload documentation

### 8. **DatabaseManager**
SQLite-based persistence layer storing:
- Scan metadata and timing
- Target discovery results
- Parameter findings
- Vulnerability details with evidence
- Report generation data

## 🎮 Usage Guide

### Quick Start
```bash
python3 Judgement.py
```

### Main Menu Options

1. **Intelligent Target Discovery**: Discover additional attack surfaces
2. **Parameter Discovery**: Find hidden parameters and input points
3. **Directory Fuzzing**: Enumerate web directories and files
4. **Parameter Fuzzing**: Test parameters for vulnerabilities
5. **Brute Force Testing**: Test login forms with credential lists
6. **Full Intelligent Assessment**: Complete automated security assessment
7. **View Reports**: Access generated security reports
8. **View Vulnerable Fields**: Review discovered vulnerabilities
9. **Configuration**: Adjust scan parameters and settings
10. **Exit**: Clean shutdown

### Configuration Options

- **Scan Depth**: quick, normal, deep, thorough
- **Thread Count**: 1-100 concurrent operations
- **Timeout**: Request timeout in seconds  
- **Delay**: Inter-request delay for rate limiting
- **Reporting Format**: html, json output formats

### Example Usage

#### 1. Full Intelligent Assessment
```bash
# Run complete automated assessment
Select option: 6
Enter target URL: https://example.com
```

#### 2. Directory Fuzzing
```bash
# Discover hidden directories and files
Select option: 3  
Enter target URL: https://example.com
```

#### 3. Parameter Fuzzing
```bash
# Test parameters for vulnerabilities
Select option: 4
Enter target URL: https://example.com/search?q=test
```

## 📊 Output & Reporting

### Generated Files
- **HTML Reports**: Comprehensive visual reports in `reports/`
- **JSON Exports**: Machine-readable data in `reports/`
- **Database**: SQLite database `judgement.db` with all findings
- **Logs**: Detailed execution logs in `logs/`
- **Payloads**: Generated payload files in `payloads/`
- **Wordlists**: Custom wordlists in `wordlists/`

### Report Contents
- Executive summary with vulnerability counts
- Detailed findings with severity ratings
- Evidence and payload documentation
- Target and parameter inventories
- Scan metadata and timing

## ⚠️ Legal & Ethical Use

**FOR AUTHORIZED SECURITY TESTING ONLY**

- Only use against systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Use for defensive security purposes only

## 🔧 Technical Architecture

### Class Structure
```
Judgement.py (3,004 lines)
├── Configuration Management
├── DatabaseManager - SQLite persistence
├── Logger - Centralized logging
├── SecListsManager - Wordlist integration
├── PayloadGenerator - Vulnerability payloads
├── WordlistManager - Dynamic wordlist generation
├── IntelligentTargetDiscovery - Target enumeration
├── IntelligentParameterDiscovery - Parameter mining
├── AdvancedFuzzer - Multi-mode fuzzing
├── DeepBruteForcer - Credential testing
├── ReportGenerator - Professional reporting
├── JudgementOrchestrator - Main orchestration
└── JudgementCLI - Interactive interface
```

### Database Schema
```sql
-- Core tables for scan management
scans, targets, parameters, findings, vulnerable_fields

-- Relationships support complex assessment tracking
scan_id → targets → parameters → findings
```

### Threading Model
- Configurable worker threads (default: 50)
- Thread-safe database operations with connection pooling
- Progress tracking with Rich library components

## 🔍 Advanced Features

### SecLists Integration
- Automatic SecLists download and integration
- 1,000+ directory wordlist entries
- 252 credential combinations  
- 772 additional specialized wordlists

### Intelligent Detection
- Response analysis for vulnerability indicators
- Content-based pattern matching
- Status code and timing analysis
- False positive reduction algorithms

### Multi-Phase Assessment
1. **Target Discovery**: Expand attack surface
2. **Parameter Discovery**: Map input points
3. **Directory Fuzzing**: Find hidden content
4. **Parameter Fuzzing**: Test for vulnerabilities
5. **Brute Force Testing**: Credential attacks
6. **Report Generation**: Professional documentation

## 🚀 Performance Characteristics

- **Multi-threaded**: Up to 100 concurrent operations
- **Memory Efficient**: SQLite backend with connection pooling
- **Rate Limited**: Configurable delays for target protection
- **Progress Tracking**: Real-time updates with Rich progress bars
- **Scalable**: Handles large target sets and parameter lists

## 🛠️ Development & Integration

### Extending Judgement
- Modular class structure for easy extension
- Plugin-friendly payload system
- Configurable reporting templates
- Database schema supports custom fields

### API Integration
- JSON export format for automation
- SQLite database for direct queries
- Standardized finding schema
- Programmatic configuration options

---

**Version**: 5.0  
**Author**: Security Research Team  
**License**: For authorized security testing only