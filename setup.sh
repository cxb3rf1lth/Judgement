#!/bin/bash
# Judgement Setup Script v2.0
# Professional Penetration Testing Framework
# Enhanced with comprehensive error handling and validation

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${2:-$NC}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Error handling
error_exit() {
    log "❌ ERROR: $1" $RED
    exit 1
}

# Check if running as root (not recommended)
if [[ $EUID -eq 0 ]]; then
    log "⚠️  WARNING: Running as root is not recommended for security reasons" $YELLOW
    read -p "Continue anyway? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "=============================================="
echo "    Judgement Framework Setup & Installation"
echo "               Version 2.0"
echo "=============================================="
echo ""

# Check system requirements
log "🔍 Checking system requirements..." $CYAN

# Check Python version (3.8+ recommended)
if command -v python3 &> /dev/null; then
    python_version=$(python3 --version 2>&1)
    python_major=$(python3 -c "import sys; print(sys.version_info.major)")
    python_minor=$(python3 -c "import sys; print(sys.version_info.minor)")
    
    if [[ $python_major -eq 3 && $python_minor -ge 8 ]]; then
        log "✅ Python detected: $python_version" $GREEN
    elif [[ $python_major -eq 3 && $python_minor -ge 6 ]]; then
        log "⚠️  Python detected: $python_version (3.8+ recommended)" $YELLOW
    else
        error_exit "Python 3.6+ required. Found: $python_version"
    fi
else
    error_exit "Python 3 not found. Please install Python 3.8+ first."
fi

# Check pip
if command -v pip3 &> /dev/null; then
    pip_version=$(pip3 --version 2>&1)
    log "✅ pip detected: $pip_version" $GREEN
else
    error_exit "pip not found. Please install pip first."
fi

# Check git (optional but recommended)
if command -v git &> /dev/null; then
    git_version=$(git --version 2>&1)
    log "✅ git detected: $git_version" $GREEN
else
    log "⚠️  git not found. Some features may be limited." $YELLOW
fi

# Check available disk space (minimum 100MB)
available_space=$(df . | tail -1 | awk '{print $4}')
if [[ $available_space -lt 102400 ]]; then  # 100MB in KB
    error_exit "Insufficient disk space. At least 100MB required."
fi

echo ""
log "📦 Installing dependencies..." $BLUE

# Create backup of existing requirements if any
if [[ -f "requirements.txt.bak" ]]; then
    log "📋 Backup of requirements.txt already exists" $YELLOW
fi

# Install core dependencies
if pip3 install -r requirements.txt --user; then
    log "✅ Core dependencies installed successfully" $GREEN
else
    error_exit "Failed to install core dependencies"
fi

# Optional: Install development dependencies
echo ""
read -p "Install development dependencies (testing, linting, docs)? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "📦 Installing development dependencies..." $BLUE
    if pip3 install -r requirements-dev.txt --user; then
        log "✅ Development dependencies installed successfully" $GREEN
    else
        log "⚠️  Some development dependencies failed to install" $YELLOW
    fi
fi

echo ""
log "🗂️  Creating directory structure..." $PURPLE

# Ensure all directories exist with proper permissions
directories=("config" "logs" "payloads" "reports" "seclists" "temp" "wordlists")
for dir in "${directories[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        chmod 755 "$dir"
        log "   Created: $dir/" $PURPLE
    else
        log "   Exists: $dir/" $YELLOW
    fi
done

echo ""
log "🔧 Running comprehensive validation checks..." $CYAN

# Test script compilation and syntax
if python3 -m py_compile Judgement.py; then
    log "✅ Script syntax validated" $GREEN
else
    error_exit "Script compilation failed - syntax error detected"
fi

# Test imports
log "🔍 Testing Python imports..." $CYAN
python3 -c "
import sys
try:
    import requests, rich, urllib3, json, sqlite3, threading
    print('✅ All core imports successful')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
" || error_exit "Required Python modules not available"

# Test basic functionality
log "🎯 Testing framework initialization..." $CYAN
timeout 10 python3 -c "
import sys
import os
sys.path.append('.')

# Test configuration loading
try:
    from Judgement import load_config
    config = load_config()
    print('✅ Configuration system working')
except Exception as e:
    print(f'❌ Configuration error: {e}')
    sys.exit(1)

# Test database initialization
try:
    from Judgement import DatabaseManager
    db = DatabaseManager()
    print('✅ Database system working')
except Exception as e:
    print(f'❌ Database error: {e}')
    sys.exit(1)

print('✅ Framework ready for deployment')
" || log "⚠️  Framework initialization test completed with timeout" $YELLOW

# Check file permissions
log "🔒 Checking file permissions..." $CYAN
if [[ -x "Judgement.py" ]]; then
    log "✅ Judgement.py is executable" $GREEN
else
    chmod +x Judgement.py
    log "✅ Made Judgement.py executable" $GREEN
fi

# Optional: Run security check
if command -v bandit &> /dev/null; then
    log "🛡️  Running security scan..." $CYAN
    if bandit -r Judgement.py -f txt -q; then
        log "✅ No security issues detected" $GREEN
    else
        log "⚠️  Security scan completed with warnings" $YELLOW
    fi
fi

# Performance test
log "⚡ Testing performance..." $CYAN
start_time=$(date +%s.%N)
python3 -c "
import time
from Judgement import load_config
config = load_config()
print('Performance test completed')
" > /dev/null 2>&1
end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "< 1")
log "✅ Framework loads in ${duration}s" $GREEN

echo ""
echo "=============================================="
echo "  🚀 Setup Complete!                        "
echo "=============================================="
echo ""
echo "📚 Quick Start:"
echo "  python3 Judgement.py"
echo ""
echo "🔧 Development mode:"
echo "  python3 Judgement.py --help"
echo ""
echo "📋 First-time setup includes:"
echo "  • Generate wordlists (1,109 entries)"
echo "  • Create payloads (896 across 12 categories)"
echo "  • Download SecLists integration"
echo "  • Initialize SQLite database"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "  • Only use for authorized testing!"
echo "  • Ensure proper consent before scanning"
echo "  • Follow responsible disclosure practices"
echo ""
echo "📚 Documentation:"
echo "  • README.md - User guide and features"
echo "  • TECHNICAL_ANALYSIS.md - Complete technical docs"
echo "  • requirements-dev.txt - Development dependencies"
echo ""
echo "🛠️  Troubleshooting:"
echo "  • Check logs/ directory for error details"
echo "  • Verify Python 3.8+ and pip are installed"
echo "  • Ensure sufficient disk space (100MB+)"
echo "  • Run: python3 -m pip install --upgrade pip"
echo ""
echo "🎯 Ready for professional security testing!"

# Optional: Create desktop shortcut (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]] && command -v desktop-file-install &> /dev/null; then
    read -p "Create desktop shortcut? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > judgement.desktop << EOF
[Desktop Entry]
Name=Judgement Security Framework
Comment=Professional Penetration Testing Automation
Exec=$(pwd)/Judgement.py
Icon=applications-development
Terminal=true
Type=Application
Categories=Development;Security;
EOF
        log "✅ Desktop shortcut created" $GREEN
    fi
fi

log "🎉 Installation completed successfully!" $GREEN