/*
  YARA Rule: LOLBIN (Living Off The Land Binary) Pattern Detection
  
  Detects executables and scripts using legitimate Windows binaries for malicious purposes
  Common LOLBINs: certutil, bitsadmin, msiexec, rundll32, regsvcs, regasm
*/

rule LOLBIN_certutil_Download
{
  meta:
    author = "SOC Threat Hunting Playbook"
    description = "Detect certutil.exe being used for file download"
    severity = "critical"
    
  strings:
    $certutil = "certutil" nocase ascii wide
    $urlcache = "-urlcache" nocase ascii wide
    $http = "http://" nocase ascii wide
    
  condition:
    all of them
}

rule LOLBIN_bitsadmin_Transfer
{
  meta:
    author = "SOC Threat Hunting Playbook"
    description = "Detect bitsadmin.exe being used for file transfer"
    severity = "high"
    
  strings:
    $bitsadmin = "bitsadmin" nocase ascii wide
    $transfer = "/transfer" nocase ascii wide
    $http = "http://" nocase ascii wide
    
  condition:
    all of them
}

rule LOLBIN_PowerShell_Bypass
{
  meta:
    author = "SOC Threat Hunting Playbook"
    description = "Detect PowerShell execution policy bypass"
    severity = "high"
    
  strings:
    $powershell = "powershell" nocase ascii wide
    $exec_policy = "-ExecutionPolicy" nocase ascii wide
    $bypass = "Bypass" nocase ascii wide
    
  condition:
    all of them
}
