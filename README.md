# BrowsAr - Browser Data Extraction Tool

## Overview

BrowsAr is a Windows-based data extraction utility designed to retrieve sensitive information from web browsers including Brave, Google Chrome, and Microsoft Edge. The tool supports extraction of cookies, browsing history, passwords, bookmarks, autofill data, prefetch data, Tor activity, and registry entries. It provides a graphical user interface for streamlined data access and analysis.

## System Requirements

- Windows 10 or later (Windows 11 recommended)
- Administrator privileges required
- Python 3.8+
- Minimum 2GB RAM
- SQLite3 support

## Dependencies

### Python Libraries

```
customtkinter>=5.0.0
Cryptodome>=3.15.0
pywin32>=305
psutil>=5.9.0
websocket-client>=1.3.0
requests>=2.28.0
```

### Windows APIs

- Windows CryptoAPI (win32crypt)
- Windows Security APIs (win32security)
- Windows Registry API (winreg)
- Windows Process APIs (win32api, win32con)

## Installation

1. Install Python 3.8 or higher from python.org
2. Clone or extract the BrowsAr repository
3. Install required dependencies:

```bash
pip install -r requirements.txt
```

4. Grant Administrator privileges to the Python executable or run the script with elevated permissions

## Project Structure

```
BrowsAr/
├── browsar_main.py              # Main application entry point with GUI
├── brave_autofill.py            # Brave autofill data extraction
├── brave_bookmark.py            # Brave bookmark extraction
├── brave_cookies.py             # Brave cookie extraction and decryption
├── brave_downloads.py           # Brave download history
├── brave_history.py             # Brave browsing history
├── brave_passwords.py           # Brave password vault extraction
├── brave_prefetch.py            # Brave prefetch data analysis
├── brave_registry.py            # Brave registry data extraction
├── brave_tor.py                 # Brave Tor network activity detection
├── chrome_downloads.py          # Chrome download history
├── chrome_passwords.py          # Chrome password vault extraction
├── chrome_prefetch.py           # Chrome prefetch data analysis
├── chrome_registry.py           # Chrome registry data extraction
├── edge_downloads.py            # Edge download history
├── edge_registry.py             # Edge registry data extraction
├── edge_prefetch.py             # Edge prefetch data analysis
└── hex_viewer.py                # Binary data hex viewer utility
```

## Key Features

### Browser Support
- Brave Browser
- Google Chrome
- Microsoft Edge

### Data Extraction Capabilities
- Autofill entries (names, addresses, email, phone)
- Bookmarks and favorites
- Encrypted cookies
- Download history with metadata
- Browsing history with timestamps
- Stored passwords with decryption
- Prefetch analysis for access patterns
- System registry entries
- Tor activity detection
- Binary data visualization

### Technical Capabilities
- Cryptographic decryption of stored credentials
- Direct SQLite database access
- Windows Registry parsing
- Process token impersonation for elevated access
- AES-256 decryption support
- Chrome's custom encryption scheme handling
- Tor detection via ROT13 decoding

## Core Components

### System Access Module
- Administrator privilege verification
- Token elevation and impersonation
- Process enumeration and access control
- Windows Security API integration

### Cryptography Module
- AES-256-GCM decryption
- Chrome password decryption
- DPAPI (Data Protection API) support
- Base64 encoding/decoding

### Data Storage Module
- SQLite database parsing
- Registry hive access
- Direct file system access to browser profiles
- Temporary file handling

### UI Module
- CustomTkinter-based GUI
- Multi-threaded data extraction
- Progress tracking and status updates
- Export functionality (CSV, JSON)

## Usage

Execute the main application:

```bash
python browsar_main.py
```

The GUI will present options to select extraction targets and data types. Elevated privileges are required for full functionality.

## Security Considerations

- This tool accesses protected system resources and encrypted data stores
- Administrator access is mandatory for certain operations
- The tool bypasses standard Windows file permissions
- Extracted data may contain sensitive credentials and personal information
- Use only on authorized systems with proper legal authorization

## Data Export

Extracted data can be exported in multiple formats:
- CSV format for spreadsheet analysis
- JSON format for programmatic access
- Raw binary data for forensic analysis

## Limitations

- Windows-only platform compatibility
- Requires administrator elevation for full data access
- Browser and profile lock status may affect data extraction
- Some encrypted data formats may be version-specific

## Troubleshooting

### Insufficient Privileges
- Run the application with Administrator privileges
- Verify UAC settings allow privilege elevation

### Database Lock Errors
- Close the target browser before extraction
- Verify no other processes are accessing browser databases

### Decryption Failures
- Ensure Windows cryptographic services are functional
- Verify DPAPI is available on the system
- Check browser version compatibility

## Legal Notice

This tool is provided for authorized forensic analysis and security research only. Unauthorized access to computer systems or personal data is illegal. Users are responsible for ensuring compliance with applicable laws and regulations.

## Version

BrowsAr v1.0

## Support

For technical issues or feature requests, refer to the project documentation or contact the development team.
