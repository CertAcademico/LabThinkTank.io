from intelligence.actor_engine import get_threat_actors
from intelligence.campaign_engine import get_campaigns

TTP_IOA_MAP: dict[str, dict] = {
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "ioa": "Outbound HTTP/HTTPS to non-whitelisted external IPs during off-hours",
        "detection_source": "SIEM / NetFlow",
        "detection_rule": "alert tcp $HOME_NET any -> $EXTERNAL_NET 80,443 (msg:\"C2 beacon pattern\"; flow:established,to_server; threshold:type both,track by_src,count 20,seconds 60;)",
        "priority": "high",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "ioa": "cmd.exe or PowerShell spawned by Office/browser process (parent-child mismatch)",
        "detection_source": "EDR / Sysmon Event ID 1",
        "detection_rule": "EventID=1 AND Image=*powershell.exe AND ParentImage IN (*WINWORD.EXE, *EXCEL.EXE, *chrome.exe, *msedge.exe)",
        "priority": "critical",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "ioa": "OpenProcess on lsass.exe from non-system process or MiniDump API call",
        "detection_source": "EDR / Sysmon Event ID 10",
        "detection_rule": "EventID=10 AND TargetImage=*lsass.exe AND NOT SourceImage IN (*svchost.exe, *csrss.exe, *wininit.exe)",
        "priority": "critical",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "ioa": "CreateRemoteThread or VirtualAllocEx in legitimate system process (svchost, explorer)",
        "detection_source": "EDR / Sysmon Event ID 8",
        "detection_rule": "EventID=8 AND TargetImage IN (*svchost.exe, *explorer.exe, *notepad.exe) AND SourceImage NOT IN (*svchost.exe)",
        "priority": "critical",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "ioa": "Email with executable attachment or URL from new external sender domain (first-time sender)",
        "detection_source": "Email Gateway / SIEM",
        "detection_rule": "email.attachment.extension IN [exe,iso,img,vbs,js,lnk] OR (email.url_count > 0 AND sender.domain.age_days < 30)",
        "priority": "high",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "ioa": "Mass file rename events (>50 files/min) with unknown/random extensions from single process",
        "detection_source": "EDR / SIEM File Audit",
        "detection_rule": "file_rename_events_per_min > 50 AND new_extension NOT IN KNOWN_EXTENSIONS AND process.reputation < 50",
        "priority": "critical",
    },
    "T1027": {
        "name": "Obfuscated Files/Information",
        "tactic": "Defense Evasion",
        "ioa": "PowerShell with -EncodedCommand flag or base64 string > 200 chars in command line",
        "detection_source": "SIEM / EDR",
        "detection_rule": "EventID=1 AND Image=*powershell.exe AND (CommandLine=*-enc* OR CommandLine=*-EncodedCommand*)",
        "priority": "medium",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "ioa": "vssadmin delete shadows or bcdedit /set recoveryenabled no executed by non-admin",
        "detection_source": "SIEM / Windows Event ID 4688",
        "detection_rule": "EventID=4688 AND (CommandLine=*vssadmin*delete*shadows* OR CommandLine=*bcdedit*/set*recoveryenabled*no*)",
        "priority": "critical",
    },
    "T1489": {
        "name": "Service Stop",
        "tactic": "Impact",
        "ioa": "Net stop or sc stop targeting >3 backup/AV/DB services within 60 seconds",
        "detection_source": "SIEM / Windows Event ID 7036",
        "detection_rule": "EventID=7036 AND ServiceState=stopped AND service.name IN [vss,wbengine,SQLWriter,MSSQLServer,WinDefend] threshold:5/60s",
        "priority": "critical",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "ioa": "Rapid execution of whoami, ipconfig, systeminfo, net user within 10 seconds post-logon",
        "detection_source": "EDR / Sysmon",
        "detection_rule": "EventID=1 AND Image IN (*whoami.exe, *ipconfig.exe, *systeminfo.exe, *net.exe) GROUP BY session HAVING count > 3 WITHIN 10s",
        "priority": "medium",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "ioa": "Authentication from geolocation >500 km from previous login within 4h (impossible travel)",
        "detection_source": "SIEM / IAM logs",
        "detection_rule": "logon.success AND geoip.distance_from_last_login_km > 500 AND time_diff_from_last_login_hours < 4",
        "priority": "high",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "ioa": ">10 failed authentication attempts from single IP against privileged accounts in 5-minute window",
        "detection_source": "SIEM / Windows Event ID 4625",
        "detection_rule": "EventID=4625 AND account.privilege=admin GROUP BY src_ip HAVING count > 10 WITHIN 300s",
        "priority": "high",
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "ioa": "File read access to browser profile/cookies directory by non-browser process",
        "detection_source": "EDR / Sysmon Event ID 11",
        "detection_rule": "EventID=11 AND TargetFilename IN (*\\Cookies*, *\\Login Data*) AND NOT Image IN (*chrome.exe, *msedge.exe, *firefox.exe)",
        "priority": "high",
    },
    "T1056": {
        "name": "Input Capture / Keylogging",
        "tactic": "Collection",
        "ioa": "SetWindowsHookEx WH_KEYBOARD_LL API call from process without UI thread",
        "detection_source": "EDR / API monitoring",
        "detection_rule": "api.call=SetWindowsHookEx AND hook_type=WH_KEYBOARD_LL AND NOT process.has_ui_thread=true",
        "priority": "high",
    },
}

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def get_ioas() -> list[dict]:
    actors = get_threat_actors()
    campaigns = get_campaigns()

    campaign_map = {c["actor"]: c for c in campaigns}
    ioas: list[dict] = []
    seen: set[str] = set()

    for actor in actors:
        campaign = campaign_map.get(actor["name"], {})
        for ttp in actor.get("ttps", []):
            if ttp in seen or ttp not in TTP_IOA_MAP:
                continue
            seen.add(ttp)
            info = TTP_IOA_MAP[ttp]
            ioas.append({
                "ttp": ttp,
                "ttp_name": info["name"],
                "tactic": info["tactic"],
                "ioa": info["ioa"],
                "detection_source": info["detection_source"],
                "detection_rule": info["detection_rule"],
                "priority": info["priority"],
                "attributed_actor": actor["name"],
                "attributed_campaign": campaign.get("name", ""),
                "campaign_status": campaign.get("status", ""),
            })

    ioas.sort(key=lambda x: PRIORITY_ORDER.get(x["priority"], 9))
    return ioas
