# BrowsAR User Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Main Interface](#main-interface)
5. [Data Extraction Procedures](#data-extraction-procedures)
6. [Export and Analysis](#export-and-analysis)
7. [Advanced Operations](#advanced-operations)
8. [Troubleshooting](#troubleshooting)
9. [Data Interpretation](#data-interpretation)

## Prerequisites

- Windows 10 or Windows 11 system
- Administrator account access
- Target browsers (Brave, Chrome, Edge) installed on the system
- **For installer:** `BrowsAR_Setup.exe` (no Python required)
- **For source:** Python 3.10+ with all dependencies installed

## Installation

### Option A — Windows Installer (recommended)

1. Run `BrowsAR_Setup.exe`
2. Accept the UAC prompt
3. Choose an install directory (default: `C:\Program Files\BrowsAR`)
4. Select whether to create a Desktop shortcut and/or Start Menu entry
5. Click **Install** and then **Finish**

No Python or additional packages are required.

### Option B — Run from source

#### Step 1: Environment Setup

1. Download and install Python 3.10+ from official sources
2. Verify Python installation:

```bash
python --version
pip --version
```

#### Step 2: Dependency Installation

Navigate to the project root and install required packages:

```bash
pip install customtkinter Cryptodome pywin32 psutil websocket-client requests pystray Pillow
```

#### Step 3: Launch

```bash
python BrowsAr\browsar_main.py
```

Windows will prompt for UAC confirmation. Click **Yes** to proceed.

## Getting Started

### Launching the Application

**From the installer:** double-click the BrowsAR desktop shortcut or find it in the Start Menu. The application auto-elevates via UAC.

**From source:**

1. Open PowerShell
2. Navigate to the project root
3. Run:

```bash
python BrowsAr\browsar_main.py
```

A splash screen with the BrowsAR logo fades in briefly while the application loads, then fades out to reveal the main window.

### Understanding the Interface

The main window contains:
- **Sidebar** — Application logo, navigation buttons, and theme toggle (Dark/Light)
- **Tab strip** — Scrollable tabs showing open analysis panels
- **Content area** — Results and details for the selected tab
- **Status bar** — Real-time extraction progress and status messages

## Main Interface

### Browser Selection

Select one or multiple browsers to scan. Available options:

- **Brave** - Brave Browser data extraction
- **Chrome** - Google Chrome user data extraction
- **Edge** - Microsoft Edge user data extraction

Multiple selections enable batch extraction across browsers simultaneously.

### Data Type Selection

Choose specific data categories to extract:

#### Cookies
Extracts encrypted cookies from browser storage. Includes:
- Cookie domain and name
- Value and expiration
- Security flags (Secure, HttpOnly)
- Decrypted content when possible

#### History
Retrieves browsing history entries containing:
- URL visited
- Page title
- Visit timestamp
- Visit count
- Last visit date

#### Passwords
Extracts stored credentials from browser vaults:
- Website/service URL
- Username
- Encrypted password
- Creation and modification timestamps

Note: Password extraction requires elevated system privileges.

#### Bookmarks
Retrieves saved bookmarks and favorites:
- Bookmark URL
- Title and description
- Folder hierarchy
- Creation timestamp

#### Autofill Data
Extracts stored autofill profiles:
- Name and email addresses
- Phone numbers
- Mailing addresses
- Billing information

#### Downloads
Lists download history with metadata:
- Downloaded file name
- Source URL
- Download path
- Download date and time
- File size
- Completion status

#### Prefetch Data
Analyzes Windows prefetch activity:
- Application execution timestamps
- File system access patterns
- System resource utilization
- Boot sequence information

#### Registry Data
Extracts browser-related registry entries:
- Installation paths
- Extension information
- User preferences
- Configuration data

#### Tor Activity
Detects and lists Tor network usage:
- Tor executable paths
- Process history
- Connection attempts
- Tor identity information

#### Browser Cache
Analyses browser cache databases:
- Cached resource URLs
- Content types and sizes
- Cache timestamps
- Response headers

## Data Extraction Procedures

### Single Browser Extraction

1. **Select Browser** - Check the checkbox for target browser (e.g., Brave)
2. **Choose Data Type** - Select one or more data categories
3. **Prepare System** - Close the target browser application
4. **Initiate Extraction** - Click the "Extract" button
5. **Monitor Progress** - Watch the status display for completion
6. **Review Results** - Extracted data appears in the results panel

### Multi-Browser Extraction

1. **Select Multiple Browsers** - Check multiple browser checkboxes
2. **Choose Data Types** - Select applicable data categories
3. **Batch Process** - Click "Extract All" for simultaneous extraction
4. **Wait for Completion** - Monitor status for each browser
5. **Review Combined Results** - Data organized by browser source

### Pre-Extraction Checklist

- Close all running instances of target browsers
- Disable browser synchronization features if possible
- Ensure sufficient disk space for temporary files
- Verify administrator privilege status
- Note extraction timestamp for reference

## Export and Analysis

### Export Options

After extraction, data can be exported to multiple formats:

#### CSV Export
- Opens Excel-compatible spreadsheet format
- Suitable for spreadsheet analysis
- Supports filtered column selection
- Preserves data relationships and hierarchy

#### JSON Export
- Structured data format for programmatic access
- Maintains data types and nested structures
- Compatible with data parsing tools
- Human-readable with proper formatting

#### Raw Binary Export
- Exports original database files
- Preserves cryptographic data
- Used for forensic analysis
- Requires specialized tools for interpretation

### Export Procedure

1. **Select Export Format** - Choose CSV, JSON, or Raw from export menu
2. **Configure Options** - Set field delimiters, encoding, and filters
3. **Choose Destination** - Specify output directory path
4. **Execute Export** - Click Export button
5. **Verify Output** - Confirm file creation and data integrity

## System Tray

BrowsAR minimises to the system tray rather than closing, so analysis results are preserved:

- **Close button (X)** — hides the window to the tray
- **Minimise button** — hides the window to the tray
- **Tray icon double-click** — restores the window
- **Tray icon right-click → Exit** — fully quits the application

## Theme Toggle

Click the **Dark / Light** button in the sidebar to switch themes. The transition is animated smoothly. The chosen theme persists for the current session.

## Advanced Operations

### Hex Viewer Utility

The included hex_viewer.py utility displays binary data in hexadecimal format:

```bash
python hex_viewer.py <filename>
```

Used for analyzing encrypted payloads, database headers, and raw binary structures.

### Browser Cache Clearing

The application includes a dedicated **Cache** tab per browser for analysing cached resources. To clear the application's own temporary extraction files, restart the application — temporary files are cleaned on each fresh run.

### Profile-Specific Extraction

For multi-profile browsers:
1. Select target browser and data type
2. The tool automatically identifies user profiles
3. Choose specific profiles or select "All Profiles"
4. Extraction proceeds for selected profiles only

### Decryption Operations

The tool automatically handles decryption for:
- Chrome user passwords
- Brave encrypted cookies
- Edge credential vault
- AES-256-GCM protected data

Manual decryption is not required; the tool manages all cryptographic operations.

## Troubleshooting

### Extraction Fails with "Access Denied"

**Cause:** Insufficient administrator privileges

**Solution:**
- Run application with right-click "Run as Administrator"
- Verify UAC is not blocking execution
- Check account has administrator group membership

### Database Lock Errors

**Cause:** Browser is running and holding database locks

**Solution:**
- Close all browser windows and processes
- Wait 30 seconds for file locks to release
- Check Task Manager for lingering browser processes
- Retry extraction operation

### No Data Retrieved

**Cause:** Target browser not installed or data not present

**Solution:**
- Verify browser is installed via Control Panel
- Confirm user has browsed with the target browser
- Check browser profile exists in default location
- Inspect application logs for specific errors

### Decryption Failures

**Cause:** Windows cryptographic services unavailable or mismatched OS

**Solution:**
- Restart system to reinitialize crypto services
- Verify Windows is updated with latest patches
- Check DPAPI service is running (services.msc)
- Extract data on same system where data was created

### Slow Performance

**Cause:** Large history or cookie databases

**Solution:**
- Extract specific data types rather than all types
- Select single browser instead of multiple
- Close unnecessary background applications
- Check available RAM and free disk space

### Export File Not Created

**Cause:** Output directory does not exist or access denied

**Solution:**
- Verify output directory path is valid
- Check directory permissions (read/write access)
- Use default output directory if custom path fails
- Ensure sufficient disk space in target location

## Data Interpretation

### Cookie Analysis

Cookies contain session tokens, authentication credentials, and tracking information:
- **Domain** - Website that set the cookie
- **Expiration** - When cookie becomes invalid
- **Secure Flag** - Indicates HTTPS-only transmission
- **HttpOnly** - Restricts JavaScript access
- **Value** - Base64-encoded cookie content

### Password Vault Interpretation

Extracted passwords represent stored credentials:
- **URL** - Associated website or service
- **Username** - Account identifier
- **Password** - Decrypted credential
- **Last Changed** - Modification timestamp
- **Modified Date** - When entry was updated

### Browsing History Analysis

History entries track user browsing patterns:
- **URL** - Exact page address visited
- **Title** - Page title at time of visit
- **Visit Time** - Exact timestamp of visit
- **Visit Count** - Total visits to this URL
- **Last Visited** - Most recent access time

### Prefetch Data Interpretation

Prefetch entries indicate system access patterns:
- **Filename** - Application or DLL being accessed
- **Run Count** - Total execution instances
- **Access Time** - Timestamp of last execution
- **File Paths** - System resources accessed by application

### Registry Data

Registry entries contain configuration and state information:
- **Key Path** - Registry hive location
- **Value Name** - Registry property name
- **Value Type** - Data type (String, DWORD, Binary)
- **Value Data** - Actual configuration value
- **Modification Time** - Last update timestamp

## Best Practices

1. **Documentation** - Record extraction date, time, and target systems
2. **Chain of Custody** - Maintain secure storage of extracted data
3. **Verification** - Cross-reference results across multiple extraction runs
4. **Legal Compliance** - Ensure authorization before extracting system data
5. **Sensitive Data** - Secure extracted credentials and personal information
6. **Regular Updates** - Keep tool and Python dependencies current
7. **Testing** - Verify functionality on non-production systems first

## Advanced Configuration

### Custom Output Paths

Edit the export configuration to specify custom output directories for each data type. Paths must be absolute and directory must exist prior to export.

### Batch Processing Scripts

Create Python scripts to automate extraction across multiple systems:
- Configure browser selection programmatically
- Implement custom export formats
- Integrate with downstream analysis tools
- Schedule automated extractions

### Data Pipeline Integration

Extracted data can be imported into:
- Database management systems (SQL, MongoDB)
- Data analysis platforms (Pandas, R)
- Forensic analysis suites
- Security information and event management (SIEM) systems

## Limitations and Known Issues

- Only functions on Windows operating systems
- Some browser versions may have incompatible database formats
- Tor detection limited to local execution evidence
- Registry extraction requires Windows registry access
- Prefetch analysis affected by Windows cleanup policies
- Some encrypted formats cannot be decrypted without system access

## Support and Reporting

For issues not covered in this guide:
1. Enable debug logging in application settings
2. Capture full application logs
3. Document steps to reproduce issue
4. Report with system specifications (Windows version, browser versions)
5. Include error messages and log excerpts

---

**Document Version:** 1.0
**Last Updated:** April 2026
**Application Version:** BrowsAr v1.0
