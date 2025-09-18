# Target File Management - Usage Guide

## Overview
The Judgement framework now supports target file management, allowing you to:
- Select target files from directory
- Create new target files with multiple targets
- Run scans on all targets in a file
- Perform full assessments on multiple targets

## Accessing Target File Management
1. Run `python3 Judgement.py`
2. Confirm authorization when prompted
3. Select option `[7] Target File Management` from the main menu

## Target File Formats
Supported file extensions: `.txt`, `.list`, `.targets`

### Example target file format:
```
# This is a comment (ignored)
https://example.com
http://api.example.com
localhost:8080
192.168.1.1:3000
# Another comment
subdomain.example.com/api
```

## Features

### 1. Select Target File from Directory
- Automatically discovers target files in current directory
- Displays numbered list for easy selection
- Supports multiple file formats

### 2. Create New Target File
- Interactive target entry (one per line)
- Automatic URL normalization (adds http:// if missing)
- Press Enter on empty line to finish

### 3. View Current Target File
- Displays all targets with count
- Shows file contents for verification

### 4. Run Single Scan Type on Target File
Available scan types:
- [1] Target Discovery
- [2] Parameter Discovery  
- [3] Directory Fuzzing
- [4] Parameter Fuzzing
- [5] Brute Force Testing

### 5. Run Full Assessment on Target File
- Performs complete security assessment on all targets
- Includes all scan types in sequence
- Optional Villain C2 integration
- Comprehensive results summary

## URL Normalization
- URLs without protocol automatically get `http://` prefix
- Comments (lines starting with #) are ignored
- Empty lines are skipped
- Supports various formats: domains, IPs, ports, paths

## Progress Tracking
- Real-time progress bars for multi-target scans
- Individual target status reporting
- Error handling for failed targets
- Comprehensive results summary

## Example Workflow
1. Create target file: `targets.txt`
2. Add targets (one per line)
3. Access Target File Management menu
4. Select "Run Full Assessment on Target File"
5. Choose your target file
6. Monitor progress and review results

## Integration
- Fully integrated with existing Judgement framework
- Compatible with all scan types
- Works with Villain C2 framework
- Maintains all security features and configurations