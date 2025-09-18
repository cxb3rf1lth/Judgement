#!/usr/bin/env python3
"""
Judgement Framework Version Information
"""

__version__ = "5.0.1"
__release_date__ = "2024-10-18"
__author__ = "Security Research Team"
__license__ = "For Authorized Security Testing Only"
__description__ = "Professional Penetration Testing Automation with Intelligent Chaining"

# Version components
VERSION_MAJOR = 5
VERSION_MINOR = 0
VERSION_PATCH = 1

# Build information
BUILD_DATE = "2024-10-18"
PYTHON_REQUIRES = ">=3.6"
PLATFORM_SUPPORT = ["Linux", "macOS", "Windows"]

# Feature information
PAYLOAD_COUNT = 896
VULNERABILITY_CATEGORIES = 12
WORDLIST_ENTRIES = 1109
DEFAULT_THREADS = 50
MAX_THREADS = 100

# Dependencies
CORE_DEPENDENCIES = [
    "requests>=2.31.0",
    "rich>=13.7.0", 
    "urllib3>=2.0.7"
]

DEV_DEPENDENCIES = [
    "pytest>=7.4.0",
    "black>=23.0.0",
    "flake8>=6.0.0",
    "mypy>=1.5.0"
]

def get_version():
    """Return the current version string."""
    return __version__

def get_version_info():
    """Return detailed version information."""
    return {
        "version": __version__,
        "release_date": __release_date__,
        "author": __author__,
        "license": __license__,
        "description": __description__,
        "python_requires": PYTHON_REQUIRES,
        "platform_support": PLATFORM_SUPPORT,
        "payload_count": PAYLOAD_COUNT,
        "vulnerability_categories": VULNERABILITY_CATEGORIES,
        "wordlist_entries": WORDLIST_ENTRIES
    }

def print_version_banner():
    """Print a formatted version banner."""
    print(f"""
╭─────────────────────────────────────────────────────────╮
│                    Judgement Framework                   │
│                       Version {__version__}                       │
├─────────────────────────────────────────────────────────┤
│ Release Date: {__release_date__}                            │
│ Author: {__author__}                    │
│ License: {__license__}        │
├─────────────────────────────────────────────────────────┤
│ Payload Arsenal: {PAYLOAD_COUNT} payloads across {VULNERABILITY_CATEGORIES} categories     │
│ Wordlist Entries: {WORDLIST_ENTRIES} comprehensive entries          │
│ Performance: Up to {MAX_THREADS} concurrent threads              │
╰─────────────────────────────────────────────────────────╯
""")

if __name__ == "__main__":
    print_version_banner()
    print("Detailed Version Information:")
    import json
    print(json.dumps(get_version_info(), indent=2))