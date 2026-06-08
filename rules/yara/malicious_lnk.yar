/*
  YARA Rule: Malicious LNK (Windows Shortcut) Detection
  
  Author: SOC Threat Hunting Playbook
  Date: 2026-06-07
  Description: Detects malicious Windows LNK files based on:
    1. LNK file header (magic bytes)
    2. Suspicious embedded commands
    3. LOLBIN abuse patterns
    4. Download/execution indicators
    
  Lab Examples:
    - Lab #3: certutil.exe with -urlcache downloading to ProgramData
    - Example #3: PowerShell creating scheduled tasks
    
  Detection Method: File signature + string pattern matching
  Confidence: 95% when all conditions met
*/

rule Malicious_LNK_Shortcut_With_LOLBIN
{
  meta:
    author = "SOC Threat Hunting Playbook"
    description = "Detect LNK files containing LOLBIN abuse patterns"
    date = "2026-06-07"
    severity = "critical"
    confidence = "high"
    rule_id = "malicious_lnk_001"
    
  strings:
    // LNK file header (magic bytes - all LNK files start with this)
    $lnk_header = {4C 00 00 00 01 14 02 00}
    
    // LOLBIN patterns
    $certutil = "certutil" nocase ascii wide
    $bitsadmin = "bitsadmin" nocase ascii wide
    $msiexec = "msiexec" nocase ascii wide
    $rundll32 = "rundll32" nocase ascii wide
    $regsvcs = "regsvcs" nocase ascii wide
    
    // Download/execute flags
    $urlcache = "-urlcache" nocase ascii wide
    $split = "-split" nocase ascii wide
    $force = "-f" nocase ascii wide
    $command = "-command" nocase ascii wide
    $executionpolicy = "ExecutionPolicy" nocase ascii wide
    $bypass = "Bypass" nocase ascii wide
    
    // Network indicators
    $http = "http://" nocase ascii wide
    $ftp = "ftp://" nocase ascii wide
    
    // Persistence indicators
    $schtask = "schtask" nocase ascii wide
    $register_task = "Register-ScheduledTask" nocase ascii wide
    
    // Writable directories (common payload storage)
    $programdata = "ProgramData" nocase ascii wide
    $temp = "\\Temp\\" nocase ascii wide
    
  condition:
    $lnk_header at 0 and
    (
      ($certutil and $urlcache) or
      ($certutil and $bypass) or
      ($bitsadmin and $http) or
      ($register_task and $bypass)
    )
}

rule Suspicious_LNK_Script_Execution
{
  meta:
    author = "SOC Threat Hunting Playbook"
    description = "Detect LNK files executing scripts"
    date = "2026-06-07"
    severity = "high"
    confidence = "high"
    
  strings:
    $lnk_header = {4C 00 00 00 01 14 02 00}
    $wscript = "wscript" nocase ascii wide
    $cscript = "cscript" nocase ascii wide
    $powershell = "powershell" nocase ascii wide
    $js_ext = ".js" nocase ascii wide
    $vbs_ext = ".vbs" nocase ascii wide
    
  condition:
    $lnk_header at 0 and
    (($wscript or $cscript) and ($js_ext or $vbs_ext))
}
