#!/usr/bin/env python3
"""
Judgement Framework Installation Validator
Comprehensive testing script to validate installation and functionality
"""

import sys
import os
import time
import subprocess
import importlib
import json
from pathlib import Path

# Color codes for output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'  # No Color

def log(message, color=NC):
    """Log a message with color and timestamp."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{color}[{timestamp}] {message}{NC}")

def check_python_version():
    """Check Python version compatibility."""
    log("🐍 Checking Python version...", CYAN)
    
    version = sys.version_info
    if version.major == 3 and version.minor >= 6:
        if version.minor >= 8:
            log(f"✅ Python {version.major}.{version.minor}.{version.micro} (recommended)", GREEN)
        else:
            log(f"⚠️  Python {version.major}.{version.minor}.{version.micro} (minimum supported)", YELLOW)
        return True
    else:
        log(f"❌ Python {version.major}.{version.minor}.{version.micro} not supported. Requires 3.6+", RED)
        return False

def check_dependencies():
    """Check if all required dependencies are installed."""
    log("📦 Checking dependencies...", CYAN)
    
    required_packages = [
        ("requests", "2.25.0"),
        ("rich", "13.0.0"),
        ("urllib3", "1.26.0")
    ]
    
    optional_packages = [
        ("pytest", "7.4.0"),
        ("black", "23.0.0"),
        ("flake8", "6.0.0"),
        ("mypy", "1.5.0")
    ]
    
    success_count = 0
    
    # Check required packages
    for package, min_version in required_packages:
        try:
            module = importlib.import_module(package)
            if hasattr(module, '__version__'):
                version = module.__version__
                log(f"✅ {package} {version} installed", GREEN)
            else:
                log(f"✅ {package} installed (version unknown)", GREEN)
            success_count += 1
        except ImportError:
            log(f"❌ {package} not installed", RED)
    
    # Check optional packages
    log("🔧 Checking optional development packages...", CYAN)
    for package, min_version in optional_packages:
        try:
            module = importlib.import_module(package)
            if hasattr(module, '__version__'):
                version = module.__version__
                log(f"✅ {package} {version} (dev tool)", BLUE)
            else:
                log(f"✅ {package} (dev tool)", BLUE)
        except ImportError:
            log(f"⚠️  {package} not installed (optional)", YELLOW)
    
    return success_count == len(required_packages)

def check_file_structure():
    """Check if required files and directories exist."""
    log("🗂️  Checking file structure...", CYAN)
    
    required_files = [
        "Judgement.py",
        "requirements.txt",
        "requirements-dev.txt",
        "setup.sh",
        "README.md",
        "TECHNICAL_ANALYSIS.md",
        "CHANGELOG.md",
        "version.py",
        ".gitignore"
    ]
    
    success = True
    for file in required_files:
        if os.path.exists(file):
            size = os.path.getsize(file)
            log(f"✅ {file} ({size:,} bytes)", GREEN)
        else:
            log(f"❌ {file} missing", RED)
            success = False
    
    return success

def test_script_compilation():
    """Test if the main script compiles without syntax errors."""
    log("🔧 Testing script compilation...", CYAN)
    
    try:
        with open("Judgement.py", "r") as f:
            code = f.read()
        
        compile(code, "Judgement.py", "exec")
        log("✅ Script compiles successfully", GREEN)
        return True
    except SyntaxError as e:
        log(f"❌ Syntax error: {e}", RED)
        log(f"   Line {e.lineno}: {e.text}", RED)
        return False
    except Exception as e:
        log(f"❌ Compilation error: {e}", RED)
        return False

def test_imports():
    """Test if all imports in the main script work."""
    log("📥 Testing imports...", CYAN)
    
    try:
        sys.path.insert(0, os.getcwd())
        
        # Test basic imports
        import requests
        import rich
        import urllib3
        import json
        import sqlite3
        import threading
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        
        log("✅ All core imports successful", GREEN)
        
        # Test version import
        try:
            import version
            log(f"✅ Version module imported: v{version.get_version()}", GREEN)
        except ImportError:
            log("⚠️  Version module not found", YELLOW)
        
        return True
    except ImportError as e:
        log(f"❌ Import error: {e}", RED)
        return False

def test_basic_functionality():
    """Test basic framework functionality."""
    log("🎯 Testing basic functionality...", CYAN)
    
    try:
        # Test configuration loading
        from Judgement import load_config
        config = load_config()
        log("✅ Configuration system working", GREEN)
        
        # Test database initialization
        from Judgement import DatabaseManager
        db = DatabaseManager()
        log("✅ Database system working", GREEN)
        
        # Test logger
        from Judgement import Logger
        logger = Logger()
        log("✅ Logging system working", GREEN)
        
        return True
    except Exception as e:
        log(f"❌ Functionality test failed: {e}", RED)
        return False

def test_performance():
    """Test framework performance and startup time."""
    log("⚡ Testing performance...", CYAN)
    
    start_time = time.time()
    
    try:
        from Judgement import load_config
        config = load_config()
        
        end_time = time.time()
        duration = end_time - start_time
        
        if duration < 2.0:
            log(f"✅ Fast startup: {duration:.2f}s", GREEN)
        elif duration < 5.0:
            log(f"⚠️  Moderate startup: {duration:.2f}s", YELLOW)
        else:
            log(f"❌ Slow startup: {duration:.2f}s", RED)
        
        return duration < 10.0  # Fail if takes more than 10 seconds
    except Exception as e:
        log(f"❌ Performance test failed: {e}", RED)
        return False

def test_security_features():
    """Test security features and validations."""
    log("🛡️  Testing security features...", CYAN)
    
    # Check for security patterns in code
    try:
        with open("Judgement.py", "r") as f:
            code = f.read()
        
        security_checks = [
            ("Authorization prompt", "authorization" in code.lower()),
            ("Rate limiting", "delay" in code.lower()),
            ("SSL warning disable", "disable_warnings" in code),
            ("User agent header", "user-agent" in code.lower() or "user_agent" in code.lower())
        ]
        
        for check_name, check_result in security_checks:
            if check_result:
                log(f"✅ {check_name} implemented", GREEN)
            else:
                log(f"⚠️  {check_name} not found", YELLOW)
        
        return True
    except Exception as e:
        log(f"❌ Security test failed: {e}", RED)
        return False

def generate_report(results):
    """Generate a validation report."""
    log("📊 Generating validation report...", CYAN)
    
    report = {
        "validation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": sys.platform,
        "results": results,
        "overall_status": "PASS" if all(results.values()) else "FAIL"
    }
    
    try:
        with open("validation_report.json", "w") as f:
            json.dump(report, f, indent=2)
        log("✅ Validation report saved to validation_report.json", GREEN)
    except Exception as e:
        log(f"⚠️  Could not save report: {e}", YELLOW)
    
    return report

def main():
    """Main validation function."""
    print(f"""
{CYAN}╭─────────────────────────────────────────────────────────╮
│            Judgement Framework Validator                 │
│               Installation & Functionality               │
╰─────────────────────────────────────────────────────────╯{NC}
""")
    
    # Run all validation tests
    tests = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("File Structure", check_file_structure),
        ("Script Compilation", test_script_compilation),
        ("Imports", test_imports),
        ("Basic Functionality", test_basic_functionality),
        ("Performance", test_performance),
        ("Security Features", test_security_features)
    ]
    
    results = {}
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        log(f"Running {test_name} test...", BLUE)
        try:
            result = test_func()
            results[test_name] = result
            if result:
                passed += 1
            print()  # Add spacing between tests
        except Exception as e:
            log(f"❌ {test_name} test failed with exception: {e}", RED)
            results[test_name] = False
            print()
    
    # Generate final report
    report = generate_report(results)
    
    # Print summary
    print(f"""
{CYAN}╭─────────────────────────────────────────────────────────╮
│                    Validation Summary                     │
╰─────────────────────────────────────────────────────────╯{NC}

{GREEN}✅ Tests Passed: {passed}/{total}{NC}
{RED if passed < total else GREEN}❌ Tests Failed: {total - passed}/{total}{NC}

Overall Status: {GREEN if report['overall_status'] == 'PASS' else RED}{report['overall_status']}{NC}
""")
    
    if report['overall_status'] == 'PASS':
        print(f"{GREEN}🎉 Judgement Framework is ready for use!{NC}")
        return 0
    else:
        print(f"{RED}⚠️  Please fix the failing tests before using Judgement.{NC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())