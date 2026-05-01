/// Living Off the Land Binaries and Scripts (LOLBAS) detection.
/// Detects abuse of trusted system binaries for malicious purposes.
/// Reference: https://lolbas-project.github.io
use once_cell::sync::Lazy;
use std::collections::HashMap;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LolbasEntry {
    pub name: &'static str,
    pub description: &'static str,
    pub mitre: &'static str,
    /// Suspicious argument patterns
    pub suspicious_args: &'static [&'static str],
}

pub static LOLBAS_DB: Lazy<HashMap<&'static str, LolbasEntry>> = Lazy::new(|| {
    let entries = vec![
        LolbasEntry {
            name: "certutil.exe",
            description: "Certificate utility abused for download/decode",
            mitre: "T1105,T1140",
            suspicious_args: &[
                "-urlcache",
                "-decode",
                "-encode",
                "-ping",
                "http://",
                "https://",
                "ftp://",
            ],
        },
        LolbasEntry {
            name: "regsvr32.exe",
            description: "Register DLL — abused to run remote scriptlets (Squiblydoo)",
            mitre: "T1218.010",
            suspicious_args: &[
                "/s", "/u", "/n", "/i:", "http://", "https://", ".sct", "scrobj",
            ],
        },
        LolbasEntry {
            name: "mshta.exe",
            description: "HTML Application host — executes HTA files",
            mitre: "T1218.005",
            suspicious_args: &["vbscript:", "javascript:", "http://", "https://", ".hta"],
        },
        LolbasEntry {
            name: "wscript.exe",
            description: "Windows Script Host",
            mitre: "T1059.005",
            suspicious_args: &[".vbs", ".js", ".jse", ".vbe", "http://", "//e:"],
        },
        LolbasEntry {
            name: "cscript.exe",
            description: "Console Script Host",
            mitre: "T1059.005",
            suspicious_args: &[".vbs", ".js", ".jse", ".vbe", "http://", "//e:"],
        },
        LolbasEntry {
            name: "rundll32.exe",
            description: "Run DLL as app — heavily abused",
            mitre: "T1218.011",
            suspicious_args: &[
                "javascript:",
                "http://",
                "shell32.dll,ShellExec",
                "url.dll,FileProtocolHandler",
                ",#",
            ],
        },
        LolbasEntry {
            name: "msiexec.exe",
            description: "Windows Installer",
            mitre: "T1218.007",
            suspicious_args: &["/i", "/q", "http://", "https://", "/quiet", "msi.dll"],
        },
        LolbasEntry {
            name: "powershell.exe",
            description: "PowerShell — most abused LOLBin",
            mitre: "T1059.001",
            suspicious_args: &[
                "-enc",
                "-encoded",
                "-nop",
                "-noprofile",
                "-w hidden",
                "-windowstyle hidden",
                "-exec bypass",
                "-executionpolicy bypass",
                "iex",
                "invoke-expression",
                "downloadstring",
                "downloadfile",
                "webclient",
                "frombase64",
                "bypass",
                "-noninteractive",
                "hidden",
            ],
        },
        LolbasEntry {
            name: "pwsh.exe",
            description: "PowerShell Core",
            mitre: "T1059.001",
            suspicious_args: &[
                "-enc",
                "-encoded",
                "-nop",
                "-noprofile",
                "-w hidden",
                "-exec bypass",
                "iex",
                "invoke-expression",
                "downloadstring",
            ],
        },
        LolbasEntry {
            name: "cmd.exe",
            description: "Windows Command Prompt",
            mitre: "T1059.003",
            suspicious_args: &["/c", "echo", "^", "&&", "||", ">", "set /p=", "for /f"],
        },
        LolbasEntry {
            name: "bitsadmin.exe",
            description: "Background Intelligent Transfer Service admin",
            mitre: "T1197",
            suspicious_args: &[
                "/transfer",
                "/addfile",
                "/setnotifycmdline",
                "http://",
                "https://",
            ],
        },
        LolbasEntry {
            name: "wmic.exe",
            description: "WMI command-line — process creation, lateral movement",
            mitre: "T1047",
            suspicious_args: &[
                "process call create",
                "shadowcopy delete",
                "/node:",
                "os get",
                "startup",
            ],
        },
        LolbasEntry {
            name: "msbuild.exe",
            description: "Microsoft Build Engine — executes inline C# tasks",
            mitre: "T1127.001",
            suspicious_args: &[".proj", ".csproj", ".targets", "UsingTask"],
        },
        LolbasEntry {
            name: "installutil.exe",
            description: ".NET install utility — proxy execution",
            mitre: "T1218.004",
            suspicious_args: &["/logfile=", "/logtoconsole=false", "/u"],
        },
        LolbasEntry {
            name: "regasm.exe",
            description: "Register .NET assembly — proxy execution",
            mitre: "T1218.009",
            suspicious_args: &["/u", ".dll"],
        },
        LolbasEntry {
            name: "regsvcs.exe",
            description: "Register .NET component services",
            mitre: "T1218.009",
            suspicious_args: &[".dll"],
        },
        LolbasEntry {
            name: "odbcconf.exe",
            description: "ODBC config — executes DLLs via REGSVR action",
            mitre: "T1218.008",
            suspicious_args: &["/a", "regsvr", ".dll", "rsp"],
        },
        LolbasEntry {
            name: "cmstp.exe",
            description: "Connection Manager Profile Installer",
            mitre: "T1218.003",
            suspicious_args: &["/ni", "/s", ".inf"],
        },
        LolbasEntry {
            name: "esentutl.exe",
            description: "Database utility — file copy bypass",
            mitre: "T1003.003",
            suspicious_args: &["/y", "/vss", "/d", "NTDS"],
        },
        LolbasEntry {
            name: "expand.exe",
            description: "Expand compressed files",
            mitre: "T1105",
            suspicious_args: &["\\\\", "http://", ".cab"],
        },
        LolbasEntry {
            name: "extrac32.exe",
            description: "CAB extraction — file download proxy",
            mitre: "T1105",
            suspicious_args: &["/y", "http://", "/c"],
        },
        LolbasEntry {
            name: "findstr.exe",
            description: "Search strings — file download via /v flag",
            mitre: "T1105",
            suspicious_args: &["/v", "/s", "/i"],
        },
        LolbasEntry {
            name: "mavinject.exe",
            description: "Microsoft Application Virtualization Injector",
            mitre: "T1055.001",
            suspicious_args: &["/injectrunning", "/pid"],
        },
        LolbasEntry {
            name: "ntdsutil.exe",
            description: "Active Directory database tool — credential dumping",
            mitre: "T1003.003",
            suspicious_args: &["ac in ntds", "ifm", "create full", "snapshot"],
        },
        LolbasEntry {
            name: "schtasks.exe",
            description: "Scheduled tasks — persistence",
            mitre: "T1053.005",
            suspicious_args: &[
                "/create", "/tr", "/sc", "/ru", "system", "onlogon", "onstart",
            ],
        },
        LolbasEntry {
            name: "at.exe",
            description: "Task scheduler — persistence (legacy)",
            mitre: "T1053.002",
            suspicious_args: &[],
        },
        LolbasEntry {
            name: "net.exe",
            description: "Network commands — discovery/lateral movement",
            mitre: "T1069,T1087",
            suspicious_args: &["user /add", "localgroup administrators", "use \\\\", "view"],
        },
        LolbasEntry {
            name: "netsh.exe",
            description: "Network shell — firewall bypass, port forwarding",
            mitre: "T1090",
            suspicious_args: &[
                "portproxy",
                "add portproxy",
                "interface portproxy",
                "firewall add",
            ],
        },
        LolbasEntry {
            name: "reg.exe",
            description: "Registry tool — persistence, credential access",
            mitre: "T1012,T1547",
            suspicious_args: &["save", "export", "add", "hklm\\sam", "hklm\\system", "run"],
        },
        LolbasEntry {
            name: "forfiles.exe",
            description: "File selection — command execution bypass",
            mitre: "T1059.003",
            suspicious_args: &["/p", "/m", "/c", "cmd", "echo"],
        },
        LolbasEntry {
            name: "pcalua.exe",
            description: "Program Compatibility Assistant — proxy execution",
            mitre: "T1218",
            suspicious_args: &["-a", "-c"],
        },
        LolbasEntry {
            name: "xwizard.exe",
            description: "Extensible Wizard Host — DLL side-loading",
            mitre: "T1218",
            suspicious_args: &[],
        },
        // macOS specific
        LolbasEntry {
            name: "osascript",
            description: "macOS AppleScript — UAC bypass, execution",
            mitre: "T1059.002",
            suspicious_args: &[
                "-e",
                "do shell script",
                "administrator privileges",
                "with administrator",
            ],
        },
        LolbasEntry {
            name: "curl",
            description: "File download — dropper",
            mitre: "T1105",
            suspicious_args: &["-o", "--output", "-O", "http://", "bash", "sh"],
        },
        LolbasEntry {
            name: "python",
            description: "Python interpreter — execution",
            mitre: "T1059.006",
            suspicious_args: &[
                "-c",
                "exec(",
                "import socket",
                "import subprocess",
                "base64",
            ],
        },
        LolbasEntry {
            name: "python3",
            description: "Python 3 interpreter",
            mitre: "T1059.006",
            suspicious_args: &[
                "-c",
                "exec(",
                "import socket",
                "import subprocess",
                "base64",
            ],
        },
        // Linux specific
        LolbasEntry {
            name: "wget",
            description: "File download — dropper",
            mitre: "T1105",
            suspicious_args: &["-O", "--output-document", "-q", "http://", "bash", "sh"],
        },
        LolbasEntry {
            name: "bash",
            description: "Bash shell",
            mitre: "T1059.004",
            suspicious_args: &["-i", "-c", "/dev/tcp/", "/dev/udp/", "base64", ">&"],
        },
    ];

    entries.into_iter().map(|e| (e.name, e)).collect()
});

pub fn check_process(name: &str, cmdline: &str) -> Option<(&'static LolbasEntry, Vec<String>)> {
    let name_lower = name.to_lowercase();
    let cmd_lower = cmdline.to_lowercase();

    let entry = LOLBAS_DB.get(name_lower.as_str()).or_else(|| {
        // Match without extension
        let stem = name_lower.trim_end_matches(".exe");
        LOLBAS_DB.get(stem)
    })?;

    let matched_args: Vec<String> = entry
        .suspicious_args
        .iter()
        .filter(|&&arg| cmd_lower.contains(&arg.to_lowercase()))
        .map(|&s| s.to_string())
        .collect();

    if matched_args.is_empty() && !entry.suspicious_args.is_empty() {
        return None;
    }

    Some((entry, matched_args))
}

#[allow(dead_code)]
pub fn is_lolbas(process_name: &str) -> bool {
    let name_lower = process_name.to_lowercase();
    LOLBAS_DB.contains_key(name_lower.as_str())
        || LOLBAS_DB.contains_key(name_lower.trim_end_matches(".exe"))
}
