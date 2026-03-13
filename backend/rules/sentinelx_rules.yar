/*
    SentinelX YARA Ruleset v2.0
    ============================
    Static signature rules for known malware families.
    Auto-generated rules are appended to: rules/auto_generated.yar
    
    References:
    [1] V. Alvarez, "YARA: The pattern matching swiss knife," 2013
    [14] The YARA Project, ReadTheDocs, 2024
*/

import "pe"
import "math"

// ── Ransomware Family Rules ────────────────────────────────────────────────

rule SentinelX_Ransomware_WannaCry {
    meta:
        description = "WannaCry ransomware — EternalBlue propagation variant"
        family      = "Ransomware.WannaCry"
        severity    = "CRITICAL"
        author      = "SentinelX Engine"
    strings:
        $s1 = "WannaDecryptor" ascii wide
        $s2 = "wncry" ascii
        $s3 = ".WNCRY" ascii
        $s4 = "WannaCry" ascii
        $ransom = "bitcoin" nocase ascii
        $ext    = "@Please_Read_Me@.txt" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (2 of ($s*) or ($ransom and $ext))
}

rule SentinelX_Ransomware_LockBit {
    meta:
        description = "LockBit 2.0/3.0 ransomware indicators"
        family      = "Ransomware.LockBit"
        severity    = "CRITICAL"
    strings:
        $s1 = "LockBit" ascii
        $s2 = "Restore-My-Files.txt" ascii
        $s3 = ".lockbit" ascii
        $anti_av = "taskkill" nocase ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($s*) or ($anti_av and math.entropy(0, filesize) >= 7.0))
}

// ── Trojan / RAT Rules ────────────────────────────────────────────────────

rule SentinelX_Trojan_AgentTesla {
    meta:
        description = "AgentTesla infostealer — keylogger + credential theft"
        family      = "Trojan.AgentTesla"
        severity    = "HIGH"
    strings:
        $s1 = "AgentTesla" ascii
        $s2 = "SmtpClient" ascii
        $s3 = "get_Clipboard" ascii
        $key = "KeyLogger" nocase ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of them)
}

rule SentinelX_RAT_AsyncRAT {
    meta:
        description = "AsyncRAT — open-source remote access trojan"
        family      = "RAT.AsyncRAT"
        severity    = "HIGH"
    strings:
        $s1 = "AsyncRAT" ascii
        $s2 = "Pastebin" ascii
        $s3 = "GetScreen" ascii
        $mutex = "AsyncMutex" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

// ── Dropper / Loader Rules ────────────────────────────────────────────────

rule SentinelX_Dropper_GuLoader {
    meta:
        description = "GuLoader shellcode dropper — NSIS-based"
        family      = "Dropper.GuLoader"
        severity    = "HIGH"
    strings:
        $s1 = "GuLoader" ascii
        $shell = { 60 89 E5 31 D2 64 8B 52 30 }   // shellcode stub
        $virt  = "VirtualAlloc" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or ($shell and $virt))
}

// ── Evasion Technique Rules ───────────────────────────────────────────────

rule SentinelX_AntiDebug_Evasion {
    meta:
        description = "Anti-debugging and anti-analysis techniques"
        severity    = "MEDIUM"
    strings:
        $d1 = "IsDebuggerPresent" ascii
        $d2 = "CheckRemoteDebuggerPresent" ascii
        $d3 = "NtQueryInformationProcess" ascii
        $d4 = "OutputDebugString" ascii
        $d5 = "FindWindow" ascii  // looks for analysis tools
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule SentinelX_Generic_HighEntropy_Packed {
    meta:
        description = "Generic packed/encrypted executable — high entropy"
        severity    = "MEDIUM"
        note        = "Requires LLM heuristic analysis (Path B)"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "This program cannot be run in DOS mode" ascii
    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0, filesize) >= 7.2 and
        (any of ($upx*) or
         (pe.number_of_sections <= 3 and pe.number_of_imports < 10))
}

rule SentinelX_Network_Downloader {
    meta:
        description = "Suspicious network downloader / dropper"
        severity    = "HIGH"
    strings:
        $n1 = "URLDownloadToFile" ascii
        $n2 = "InternetOpen" ascii
        $n3 = "HttpSendRequest" ascii
        $n4 = "WinHttpOpen" ascii
        $shell = "cmd.exe" nocase ascii
        $ps    = "powershell" nocase ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($n*)) and
        (1 of ($shell, $ps))
}

rule SentinelX_Infostealer_Clipboard {
    meta:
        description = "Clipboard / credential stealer indicators"
        family      = "Infostealer"
        severity    = "HIGH"
    strings:
        $c1 = "GetClipboardData" ascii
        $c2 = "CryptUnprotectData" ascii  // DPAPI credential theft
        $c3 = "OpenClipboard" ascii
        $c4 = "chrome" nocase ascii
        $c5 = "firefox" nocase ascii
        $c6 = "Login Data" ascii
    condition:
        uint16(0) == 0x5A4D and
        (($c1 or $c3) and ($c2 or $c4 or $c5 or $c6))
}
