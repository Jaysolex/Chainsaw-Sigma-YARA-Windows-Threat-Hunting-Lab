# 🔨 Chainsaw Usage Examples

## Example 1: Detect Office Macro Attack

```bash
chainsaw hunt C:\Windows\System32\winevt\Logs -s rules/sigma/office_macros.yml -o json
```

**What to look for:**
- WINWORD.EXE spawning powershell.exe
- PowerShell with -ExecutionPolicy Bypass
- Network connections to suspicious IPs

---

## Example 2: Detect LNK File Attack

```bash
chainsaw hunt C:\Windows\System32\winevt\Logs -s rules/sigma/lnk_file_execution.yml
```

**What to look for:**
- explorer.exe spawning certutil or bitsadmin
- Download commands to suspicious locations
- Parent process: explorer.exe or unknown

---

## Example 3: Detect Persistence via Registry

```bash
chainsaw hunt C:\Windows\System32\winevt\Logs -s rules/sigma/registry_run_keys.yml
```

**What to look for:**
- HKLM\Software\...\Run modifications
- Unknown processes adding registry keys
- Unusual executable paths

---

## Example 4: Hunt All Rules

```bash
chainsaw hunt C:\Windows\System32\winevt\Logs -s rules/sigma/ -o json > results.json
```

Then analyze:
```bash
jq '. | length' results.json
```

---

## Example 5: Real Attack Chain Detection

```bash
# 1. Macro execution
chainsaw hunt logs/ -s rules/sigma/office_macros.yml

# 2. Script execution
chainsaw hunt logs/ -s rules/sigma/scripts_user_folders.yml

# 3. Persistence
chainsaw hunt logs/ -s rules/sigma/scheduled_task_creation.yml

# 4. Registry changes
chainsaw hunt logs/ -s rules/sigma/registry_run_keys.yml
```

Expected timeline:
- 10:30 - Macro execution
- 10:31 - PowerShell spawned
- 10:32 - Script downloaded
- 10:33 - Task created
- 10:34 - Registry modified

---

## Example 6: Filter by MITRE Technique

```bash
chainsaw hunt logs/ -s rules/sigma/ | grep "T1053"
```

This finds all scheduled task persistence (T1053.005).
