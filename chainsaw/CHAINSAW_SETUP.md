# 🔍 Chainsaw SIEM-Less Threat Hunting Setup

## What is Chainsaw?

Chainsaw is a Windows event log analysis tool for SIEM-less threat hunting using Sigma rules.

## Key Features

- ✅ SIEM-less log analysis
- ✅ Sigma rule support
- ✅ Fast event log hunting
- ✅ MITRE ATT&CK mapping

## Installation

### On Windows:
```powershell
Invoke-WebRequest -Uri "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.1.0/chainsaw_x86_64-pc-windows-gnu.zip" -OutFile "chainsaw.zip"
Expand-Archive -Path "chainsaw.zip" -DestinationPath "C:\Tools\chainsaw"
C:\Tools\chainsaw\chainsaw.exe --version
```

### On Mac/Linux:
```bash
wget https://github.com/WithSecureLabs/chainsaw/releases/download/v2.1.0/chainsaw_x86_64-unknown-linux-gnu.tar.gz
tar -xzf chainsaw_x86_64-unknown-linux-gnu.tar.gz
chmod +x chainsaw
```

## Using Chainsaw with Our Sigma Rules

```bash
# Hunt with our rules
chainsaw hunt /path/to/logs -s rules/sigma/ -o json

# List available rules
chainsaw list-rules -s rules/sigma/

# Hunt specific rule
chainsaw hunt /path/to/logs -s rules/sigma/office_macros.yml
```

## Our 8 Sigma Rules for Chainsaw

| Rule | Detects | Output |
|------|---------|--------|
| office_macros.yml | Office→PowerShell | Event ID 1 |
| lnk_file_execution.yml | LNK+LOLBIN | Event ID 1 |
| scripts_user_folders.yml | User scripts | Event ID 1 |
| scripts_system_folders.yml | ProgramData | Event ID 1 |
| scheduled_task_creation.yml | Task persistence | Event ID 12 |
| registry_run_keys.yml | Registry persistence | Event ID 12 |
| chm_file_execution.yml | CHM files | Event ID 1 |
| hta_file_execution.yml | HTA execution | Event ID 1 |

## Quick Start

```bash
chainsaw hunt C:\Windows\System32\winevt\Logs -s rules/sigma/ -o csv
```

See CHAINSAW_EXAMPLES.md for real-world scenarios.
