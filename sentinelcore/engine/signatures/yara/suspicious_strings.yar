/*
    SentinelCore starter YARA rules.
    Add community rulesets (e.g., Yara-Rules project, Neo23x0) as the library grows.
*/

rule Suspicious_PowerShell_Download {
    meta:
        description = "Detects PowerShell download cradle patterns"
        severity = "high"
    strings:
        $s1 = "IEX" nocase
        $s2 = "DownloadString" nocase
        $s3 = "WebClient" nocase
    condition:
        2 of ($s1, $s2, $s3)
}

rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumper strings"
        severity = "critical"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "lsadump" nocase
        $d = "kerberos::list" nocase
    condition:
        any of them
}

rule Packed_Suspicious_Entropy {
    meta:
        description = "High entropy combined with suspicious API imports — possible packer"
        severity = "medium"
    strings:
        $api1 = "VirtualAlloc" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
    condition:
        2 of them
}

rule Reverse_Shell_Indicators {
    meta:
        description = "Strings commonly found in reverse shells"
        severity = "high"
    strings:
        $s1 = "/bin/sh" nocase
        $s2 = "/bin/bash" nocase
        $s3 = "socket" nocase
        $s4 = "connect" nocase
        $s5 = "recv" nocase
    condition:
        3 of them
}
