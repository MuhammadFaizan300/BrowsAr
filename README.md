# BrowsAR - Browser Forensic Suite

## Overview

BrowsAR is a Windows-based browser forensics tool designed to retrieve and analyse data from Brave, Google Chrome, and Microsoft Edge. It supports extraction of cookies, browsing history, passwords, bookmarks, autofill data, prefetch data, Tor activity, registry entries, and browser caches. The application ships as a traditional Windows installer and features a modern dark/light-themed GUI with system tray integration and a branded splash screen.

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
pystray>=0.19.0
Pillow>=10.0.0
```

### Windows APIs

- Windows CryptoAPI (win32crypt)
- Windows Security APIs (win32security)
- Windows Registry API (winreg)
- Windows Process APIs (win32api, win32con)

## Installation

### Option A — Windows Installer (recommended)

1. Run `BrowsAR_Setup.exe`
2. Follow the wizard: choose install path, optional desktop/Start Menu shortcuts
3. Launch **BrowsAR** from the desktop shortcut or Start Menu

The installer handles all dependencies and registers the application. UAC will prompt for elevation on first launch.

### Option B — Run from source

1. Install Python 3.10+ from python.org
2. Clone or extract the repository
3. Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

4. Install dependencies:

```bash
pip install customtkinter Cryptodome pywin32 psutil websocket-client requests pystray Pillow
```

5. Run with administrator privileges:

```bash
python BrowsAr\browsar_main.py
```

### Building the installer from source

Requires Python + venv set up as above, plus [NSIS](https://nsis.sourceforge.io/) installed.

```powershell
.\build.ps1
```

This runs PyInstaller then NSIS and produces `BrowsAR_Setup.exe` in the project root.

## Project Structure

```
Project/
├── build.ps1                    # Full build pipeline (PyInstaller + NSIS)
├── browsar_installer.nsi        # NSIS installer script
│
└── BrowsAr/
    ├── browsar_main.py          # Main application entry point with GUI
    ├── browsar.spec             # PyInstaller build spec
    ├── brave_autofill.py        # Brave autofill data extraction
    ├── brave_bookmark.py        # Brave bookmark extraction
    ├── brave_cookies.py         # Brave cookie extraction and decryption
    ├── brave_downloads.py       # Brave download history
    ├── brave_history.py         # Brave browsing history
    ├── brave_passwords.py       # Brave password vault extraction
    ├── brave_prefetch.py        # Brave prefetch data analysis
    ├── brave_registry.py        # Brave registry data extraction
    ├── brave_tor.py             # Brave Tor network activity detection
    ├── chrome_downloads.py      # Chrome download history
    ├── chrome_passwords.py      # Chrome password vault extraction
    ├── chrome_prefetch.py       # Chrome prefetch data analysis
    ├── chrome_registry.py       # Chrome registry data extraction
    ├── edge_downloads.py        # Edge download history
    ├── edge_registry.py         # Edge registry data extraction
    ├── edge.prefetch.py         # Edge prefetch data analysis
    ├── hex_viewer.py            # Binary data hex viewer utility
    ├── logo.png                 # Application logo (splash/sidebar/tray)
    └── browsar.ico              # Application icon (place manually before building)
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
- System registry entries (interactive explorer)
- Tor activity detection
- Browser cache analysis
- Binary data visualization

### Application Features
- Traditional Windows installer with path and shortcut selection
- Dark / Light theme toggle with smooth transitions
- System tray integration — minimise or close hides to tray; double-click to restore
- Branded splash screen with fade-in / fade-out animation
- Tabbed interface with scrollable tab strip

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

**Installed:** Launch BrowsAR from the desktop or Start Menu shortcut. The application auto-elevates via UAC.

**From source:**

```bash
python BrowsAr\browsar_main.py
```

The GUI presents a sidebar for navigation and tabbed panels for each data type. Elevated privileges are required for full functionality. Closing the window minimises the app to the system tray; right-click the tray icon to exit.

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

BrowsAR v2.0

## Support

For technical issues or feature requests, refer to the project documentation or contact the development team.
