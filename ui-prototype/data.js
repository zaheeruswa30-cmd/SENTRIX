/* SecureWatch AI — seeded synthetic dataset for the client-side demo.
   ALL data here is fabricated for demonstration. No live systems, no real hosts,
   no real users. Defensive/investigative content only — no offensive tooling and
   no response or remediation actions. */
(function () {
  'use strict';

  var SW = (window.SW = window.SW || {});

  /* ---------------- Seeded accounts (client-side only, plaintext by design in a demo) -------- */
  var USERS = [
    { id: 'u1', name: 'A. Reyes', email: 'analyst@securewatch.local', password: 'Demo1234!', role: 'Analyst', seeded: true },
    { id: 'u2', name: 'M. Cardoso', email: 'admin@securewatch.local', password: 'Admin1234!', role: 'Admin', seeded: true },
    { id: 'u3', name: 'J. Okafor', email: 'viewer@securewatch.local', password: 'Viewer1234!', role: 'Viewer', seeded: true }
  ];

  /* ---------------- Endpoints ---------------- */
  function ep(id, host, os, group, ip, risk, health, online, user, cpu, mem, disk, patch) {
    return {
      id: id, host: host, os: os, group: group, ip: ip, risk: risk, health: health,
      online: online, user: user, cpu: cpu, mem: mem, disk: disk, patchDrift: patch,
      agent: '7.4.219', lastSeen: online ? Math.floor(Math.random() * 4) + 1 + 'm ago' : '4h 12m ago'
    };
  }
  var ENDPOINTS = [
    ep('WKS-042', 'WKS-042', 'Windows 11 Pro 23H2', 'Workstations', '10.24.8.42', 88, 41, true, 'l.moreau', 34, 71, 62, 9),
    ep('WKS-017', 'WKS-017', 'Windows 11 Pro 23H2', 'Workstations', '10.24.8.17', 76, 55, true, 'd.ferreira', 22, 58, 44, 4),
    ep('WKS-031', 'WKS-031', 'Windows 10 Pro 22H2', 'Workstations', '10.24.8.31', 38, 79, true, 't.ibarra', 12, 40, 51, 1),
    ep('WKS-005', 'WKS-005', 'Windows 11 Pro 23H2', 'Workstations', '10.24.8.5', 18, 92, true, 'a.reyes', 9, 33, 38, 0),
    ep('WKS-026', 'WKS-026', 'Windows 10 Pro 22H2', 'Workstations', '10.24.8.26', 44, 74, true, 'k.nakamura', 18, 47, 66, 2),
    ep('LT-FIN-08', 'LT-FIN-08', 'macOS 14.5 Sonoma', 'Laptops', '10.24.16.8', 57, 68, true, 'p.saldana', 27, 62, 71, 3),
    ep('LT-FIN-02', 'LT-FIN-02', 'macOS 14.4 Sonoma', 'Laptops', '10.24.16.2', 31, 81, false, 'r.okonkwo', 0, 0, 58, 6),
    ep('SRV-DB-01', 'SRV-DB-01', 'Ubuntu Server 22.04 LTS', 'DB servers', '10.24.4.11', 81, 52, true, 'svc_postgres', 61, 78, 82, 11),
    ep('SRV-DB-02', 'SRV-DB-02', 'Ubuntu Server 22.04 LTS', 'DB servers', '10.24.4.12', 47, 71, true, 'svc_postgres', 39, 55, 64, 5),
    ep('SRV-APP-03', 'SRV-APP-03', 'Ubuntu Server 22.04 LTS', 'App servers', '10.24.4.33', 79, 57, true, 'svc_app', 48, 66, 49, 2),
    ep('SRV-APP-01', 'SRV-APP-01', 'Ubuntu Server 22.04 LTS', 'App servers', '10.24.4.31', 26, 86, true, 'svc_app', 31, 44, 40, 0),
    ep('SRV-FILE-02', 'SRV-FILE-02', 'Windows Server 2022', 'File servers', '10.24.4.52', 62, 66, true, 'svc_backup', 24, 51, 88, 7)
  ];

  /* ---------------- Security events ----------------
     `fields` carry the machine-readable telemetry the detection rules match on. */
  var now = Date.now();
  function mins(m) { return new Date(now - m * 60000); }
  var evSeq = 0;
  function event(o) {
    evSeq += 1;
    o.id = 'EVT-' + String(4100 + evSeq);
    o.status = o.status || 'New';
    o.fields = o.fields || {};
    return o;
  }
  var EVENTS = [
    event({ ts: mins(3), severity: 'CRITICAL', type: 'Process execution', endpoint: 'WKS-042',
      title: 'Encoded PowerShell command executed by Office child process',
      fields: { process: 'powershell.exe', parent: 'cmd.exe', grandparent: 'outlook.exe', user: 'l.moreau',
        command_line: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA', signed: true } }),
    event({ ts: mins(9), severity: 'HIGH', type: 'Authentication', endpoint: 'SRV-DB-01',
      title: 'Repeated failed SSH authentication from single source',
      fields: { user: 'root', remote_ip: '10.24.9.71', failed_count: 42, port: 22, service: 'sshd' } }),
    event({ ts: mins(14), severity: 'CRITICAL', type: 'File write', endpoint: 'WKS-017',
      title: 'Unsigned binary written to Windows Temp directory',
      fields: { process: 'wscript.exe', user: 'd.ferreira', file_path: 'C:\\Windows\\Temp\\svhost_up.exe', signed: false, size_kb: 412 } }),
    event({ ts: mins(21), severity: 'MEDIUM', type: 'Persistence', endpoint: 'LT-FIN-08',
      title: 'Scheduled task created outside the approved change window',
      fields: { process: 'launchctl', user: 'p.saldana', task_name: 'com.update.helper', schedule: 'every 30m' } }),
    event({ ts: mins(28), severity: 'HIGH', type: 'Network', endpoint: 'SRV-APP-03',
      title: 'Regular-interval outbound connection to external host',
      fields: { remote_ip: '185.203.116.44', port: 8443, interval_seconds: 60, bytes_out: 1840, process: 'node' } }),
    event({ ts: mins(36), severity: 'LOW', type: 'Removable media', endpoint: 'WKS-031',
      title: 'USB mass-storage device enrolled by end user',
      fields: { user: 't.ibarra', device: 'Kingston DT 32GB', serial: 'KDT-9931-AF', removable: true } }),
    event({ ts: mins(44), severity: 'MEDIUM', type: 'File access', endpoint: 'SRV-FILE-02',
      title: 'Bulk file read by backup service account',
      fields: { user: 'svc_backup', file_count: 1204, share: '\\\\SRV-FILE-02\\finance', window_minutes: 6 } }),
    event({ ts: mins(52), severity: 'CRITICAL', type: 'Credential access', endpoint: 'WKS-042',
      title: 'Handle opened to LSASS by non-standard process',
      fields: { process: 'rundll32.exe', target_process: 'lsass.exe', user: 'l.moreau', access_mask: '0x1010' } }),
    event({ ts: mins(61), severity: 'INFO', type: 'Agent', endpoint: 'WKS-005',
      title: 'EDR sensor updated to build 7.4.219', status: 'Resolved',
      fields: { previous: '7.4.180', current: '7.4.219' } }),
    event({ ts: mins(70), severity: 'MEDIUM', type: 'Network', endpoint: 'SRV-APP-03',
      title: 'TLS certificate pin mismatch on outbound connection',
      fields: { remote_ip: '185.203.116.44', port: 443, cert_cn: 'cdn-static.example', pinned: false } }),
    event({ ts: mins(83), severity: 'HIGH', type: 'Discovery', endpoint: 'WKS-026',
      title: 'Local administrators group enumerated from a user session',
      fields: { process: 'net.exe', command_line: 'net localgroup administrators', user: 'k.nakamura' } }),
    event({ ts: mins(95), severity: 'LOW', type: 'Authentication', endpoint: 'WKS-005',
      title: 'Off-hours interactive logon from managed workstation', status: 'Monitoring',
      fields: { user: 'a.reyes', logon_type: 2, hour_utc: 3 } }),
    event({ ts: mins(112), severity: 'MEDIUM', type: 'Process execution', endpoint: 'SRV-DB-01',
      title: 'Shell spawned by database service account',
      fields: { process: 'bash', parent: 'postgres', user: 'svc_postgres', command_line: '/bin/bash -c "psql -c copy"' } }),
    event({ ts: mins(130), severity: 'LOW', type: 'Configuration', endpoint: 'SRV-APP-01',
      title: 'Host firewall rule added by configuration management', status: 'Resolved',
      fields: { user: 'svc_ansible', rule: 'allow tcp/9100 from 10.24.4.0/24' } }),
    event({ ts: mins(148), severity: 'HIGH', type: 'Persistence', endpoint: 'WKS-017',
      title: 'Run key modified to launch binary from Temp',
      fields: { process: 'reg.exe', user: 'd.ferreira', command_line: 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Windows\\Temp\\svhost_up.exe', file_path: 'C:\\Windows\\Temp\\svhost_up.exe' } }),
    event({ ts: mins(166), severity: 'MEDIUM', type: 'Authentication', endpoint: 'SRV-DB-02',
      title: 'Failed database logons from application subnet',
      fields: { user: 'app_ro', remote_ip: '10.24.4.33', failed_count: 11, port: 5432 } }),
    event({ ts: mins(190), severity: 'INFO', type: 'Agent', endpoint: 'LT-FIN-02',
      title: 'Endpoint stopped reporting telemetry', status: 'Monitoring',
      fields: { last_checkin_minutes: 252 } }),
    event({ ts: mins(214), severity: 'LOW', type: 'Discovery', endpoint: 'WKS-031',
      title: 'Domain trust enumeration from user context',
      fields: { process: 'nltest.exe', user: 't.ibarra', command_line: 'nltest /domain_trusts' } }),
    event({ ts: mins(240), severity: 'MEDIUM', type: 'File write', endpoint: 'LT-FIN-08',
      title: 'Script written to user LaunchAgents directory',
      fields: { user: 'p.saldana', file_path: '/Users/p.saldana/Library/LaunchAgents/com.update.helper.plist', signed: false } }),
    event({ ts: mins(275), severity: 'HIGH', type: 'Network', endpoint: 'WKS-042',
      title: 'DNS queries to newly registered domain at fixed cadence',
      fields: { domain: 'sync-status-cdn.io', interval_seconds: 300, remote_ip: '185.203.116.44', process: 'powershell.exe' } }),
    event({ ts: mins(310), severity: 'MEDIUM', type: 'File access', endpoint: 'SRV-FILE-02',
      title: 'Access to finance share outside business hours',
      fields: { user: 'svc_backup', file_count: 62, share: '\\\\SRV-FILE-02\\finance', hour_utc: 2 } }),
    event({ ts: mins(350), severity: 'LOW', type: 'Configuration', endpoint: 'WKS-026',
      title: 'Screen-lock timeout extended beyond policy baseline', status: 'Triage',
      fields: { user: 'k.nakamura', value_minutes: 45, policy_minutes: 15 } }),
    event({ ts: mins(400), severity: 'CRITICAL', type: 'Process execution', endpoint: 'SRV-APP-03',
      title: 'Base64-decoded payload piped to interpreter by web service user',
      fields: { process: 'sh', parent: 'node', user: 'svc_app', command_line: 'echo SQBFAFg | base64 -d | sh', signed: false } }),
    event({ ts: mins(455), severity: 'INFO', type: 'Agent', endpoint: 'SRV-APP-01',
      title: 'Baseline configuration scan completed', status: 'Resolved',
      fields: { findings: 3, profile: 'CIS Ubuntu 22.04 L1' } })
  ];

  /* ---------------- Incidents ---------------- */
  var STAGES = ['Detection', 'Analysis', 'Correlation', 'Risk Assessment', 'Investigation', 'Resolution'];
  var INCIDENTS = [
    { id: 'INC-2291', title: 'Encoded PowerShell execution chain on WKS-042', severity: 'CRITICAL',
      endpoint: 'WKS-042', stage: 3, opened: '03 Sep 2026 19:58 UTC', analyst: 'A. Reyes',
      tags: ['T1059.001', 'T1071.001'], eventIds: ['EVT-4101', 'EVT-4108', 'EVT-4120'],
      summary: 'Outlook spawned cmd.exe which launched PowerShell with a base64 -enc payload, followed by fixed-cadence DNS beaconing from the same host.',
      resolution: '' },
    { id: 'INC-2264', title: 'SSH password spraying against SRV-DB-01', severity: 'HIGH',
      endpoint: 'SRV-DB-01', stage: 4, opened: '02 Sep 2026 08:14 UTC', analyst: 'M. Cardoso',
      tags: ['T1110'], eventIds: ['EVT-4102'],
      summary: '42 failed root SSH authentications from 10.24.9.71 within four minutes; source is an unmanaged lab host.',
      resolution: '' },
    { id: 'INC-2210', title: 'Unsigned binary staged in Windows Temp on WKS-017', severity: 'HIGH',
      endpoint: 'WKS-017', stage: 5, opened: '29 Aug 2026 11:02 UTC', analyst: 'A. Reyes',
      tags: ['T1204.002', 'T1547.001'], eventIds: ['EVT-4103', 'EVT-4115'],
      summary: 'wscript.exe wrote svhost_up.exe to C:\\Windows\\Temp and a Run key was created pointing at it.',
      resolution: 'Confirmed as a user-installed unsupported updater. Closed as true-positive/low-impact after review.' },
    { id: 'INC-2188', title: 'Bulk finance-share reads by svc_backup', severity: 'MEDIUM',
      endpoint: 'SRV-FILE-02', stage: 5, opened: '24 Aug 2026 02:41 UTC', analyst: 'M. Cardoso',
      tags: ['T1119'], eventIds: ['EVT-4107', 'EVT-4121'],
      summary: '1,204 files read from the finance share by the backup service account during an unscheduled window.',
      resolution: 'Backup window had been changed without a change record. Closed as benign after owner confirmation.' },
    { id: 'INC-2151', title: 'Recurring outbound beacon from SRV-APP-03', severity: 'HIGH',
      endpoint: 'SRV-APP-03', stage: 2, opened: '21 Aug 2026 16:30 UTC', analyst: 'A. Reyes',
      tags: ['T1071.001'], eventIds: ['EVT-4105', 'EVT-4110'],
      summary: 'Sixty-second cadence connections to 185.203.116.44:8443 with a certificate pin mismatch on the same destination.',
      resolution: '' }
  ];

  /* ---------------- Seeded demo documents (already indexed at login) ---------------- */
  var SEED_DOCS = [
    { name: 'PowerShell-Security-Policy.md', kind: 'demo', ext: 'md',
      text: [
        '# PowerShell Security Policy (SYNTHETIC DEMO DOCUMENT)',
        '',
        '## 1. Scope',
        'This policy governs Windows PowerShell and PowerShell 7 usage on all managed workstations and servers. It is written for defensive monitoring and investigation only.',
        '',
        '## 2. Encoded command execution',
        'Use of the -EncodedCommand parameter (abbreviated -enc, -en, -e) is prohibited outside of approved automation accounts. Any encoded PowerShell command line observed on a workstation must be treated as at least HIGH severity and escalated for analyst review. Investigators should capture the full command line, decode the base64 payload in an isolated analysis environment, and record the decoded intent in the incident record.',
        '',
        '## 3. Parent-child process expectations',
        'PowerShell launched by a productivity application such as outlook.exe, winword.exe or excel.exe, directly or through cmd.exe, is never expected on managed workstations. This parent-child chain is a strong indicator of a phishing-driven execution attempt and maps to MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell).',
        '',
        '## 4. Logging requirements',
        'Script block logging (Event ID 4104), module logging and transcription must be enabled on every managed endpoint. Retention is 90 days minimum. Missing 4104 events on a host where encoded PowerShell was observed is itself a finding and should be noted as an evidence gap in the analysis.',
        '',
        '## 5. Constrained language mode',
        'All user-context workstations run PowerShell in Constrained Language Mode. Detection of FullLanguage mode in a user session should be correlated with the process ancestry and the signing status of any loaded modules.',
        '',
        '## 6. Investigation checklist for encoded PowerShell',
        '1. Review the complete command line and decode the payload offline.',
        '2. Reconstruct the process ancestry three levels up from powershell.exe.',
        '3. Pull script block logs for the session and the preceding ten minutes.',
        '4. Check outbound network connections made by the PowerShell process, especially fixed-cadence DNS or HTTPS traffic.',
        '5. Verify whether LSASS was accessed by any process in the same session.',
        '6. Confirm whether the signed-in user reported a suspicious email or attachment.',
        '',
        '## 7. Beaconing correlation',
        'Fixed-interval outbound connections observed within thirty minutes of an encoded PowerShell execution on the same host should raise the composite risk score of that host and be tracked under a single incident. Reference MITRE ATT&CK T1071.001 (Application Layer Protocol: Web Protocols).',
        '',
        '## 8. Exceptions',
        'Approved automation accounts are listed in the automation register. Exceptions expire after 90 days and require re-approval. No exception permits encoded commands in an interactive user session.'
      ].join('\n') },
    { name: 'Prior-Incident-Report-INC-2210.txt', kind: 'demo', ext: 'txt',
      text: [
        'PRIOR INCIDENT REPORT — INC-2210 (SYNTHETIC DEMO DOCUMENT)',
        'Title: Unsigned binary staged in Windows Temp on WKS-017',
        'Severity: HIGH   Status: Closed (true positive, low impact)',
        'Opened: 29 Aug 2026 11:02 UTC   Analyst: A. Reyes',
        '',
        'SUMMARY',
        'wscript.exe wrote an unsigned executable named svhost_up.exe into C:\\Windows\\Temp on WKS-017. Approximately two hours later reg.exe created a HKCU Run key pointing at the same path, establishing user-level persistence. No credential access and no lateral movement were observed.',
        '',
        'DETECTION PATH',
        'The initial signal was a file-write rule for unsigned executables in Windows Temp. The persistence signal came from a registry Run key rule. Both rules fired on the same host within a single working day, and correlation on file path linked them into one incident.',
        '',
        'ANALYSIS',
        'The binary was an unsupported third-party updater installed by the end user from a download link. Static review showed no obfuscation and no network capability beyond a version check. The Run key was created by the installer, not by an external operator. Signing status was the single most useful discriminator during triage.',
        '',
        'RISK ASSESSMENT',
        'Composite host risk moved from 44 to 76 while the incident was open, driven by the unsigned-binary finding and the persistence mechanism. Risk returned to 55 after the review concluded.',
        '',
        'LESSONS LEARNED',
        '1. Unsigned executables in Windows Temp remain a high-yield detection on this fleet.',
        '2. Persistence via HKCU Run keys should always be correlated back to the file-write event on the same path.',
        '3. Analysts should confirm software provenance with the end user before escalating an unsigned-binary finding.',
        '4. Encoded PowerShell was NOT present in this incident; that distinction separated it from INC-2291.',
        '',
        'RELATED PATTERNS',
        'Similar staging paths seen historically: C:\\Windows\\Temp, C:\\Users\\Public, %APPDATA%\\Local\\Temp. MITRE ATT&CK references: T1204.002 (User Execution: Malicious File) and T1547.001 (Registry Run Keys / Startup Folder).',
        '',
        'INVESTIGATION GUIDANCE REUSED FROM THIS INCIDENT',
        'Review the writing process ancestry, verify the digital signature and publisher, list all autoruns referencing the path, and check whether the same file hash appears on any other managed endpoint.'
      ].join('\n') }
  ];

  /* ---------------- 7-day trend seed (used with live events) ---------------- */
  var TREND_DAYS = ['Aug 28', 'Aug 29', 'Aug 30', 'Aug 31', 'Sep 1', 'Sep 2'];
  var TREND_SEED = {
    CRITICAL: [1, 0, 2, 1, 1, 2], HIGH: [4, 3, 6, 5, 7, 6],
    MEDIUM: [11, 9, 14, 12, 15, 13], LOW: [22, 19, 26, 24, 28, 25]
  };

  /* ---------------- Simulated new alerts for the live feed ---------------- */
  var LIVE_ALERTS = [
    { severity: 'HIGH', type: 'Credential access', endpoint: 'WKS-042',
      title: 'LSASS handle requested by unsigned helper process',
      fields: { process: 'helper32.exe', target_process: 'lsass.exe', user: 'l.moreau', signed: false } },
    { severity: 'CRITICAL', type: 'Process execution', endpoint: 'WKS-026',
      title: 'Encoded PowerShell launched from a mounted removable volume',
      fields: { process: 'powershell.exe', parent: 'explorer.exe', user: 'k.nakamura',
        command_line: 'powershell -w hidden -enc RwBlAHQALQBQAHIAbwBjAA==', removable: true } },
    { severity: 'MEDIUM', type: 'Persistence', endpoint: 'SRV-APP-01',
      title: 'Cron entry added by application service account',
      fields: { process: 'crontab', user: 'svc_app', schedule: '*/15 * * * *' } },
    { severity: 'HIGH', type: 'Authentication', endpoint: 'SRV-DB-02',
      title: 'Burst of failed SSH authentications from lab subnet',
      fields: { user: 'admin', remote_ip: '10.24.9.88', failed_count: 27, port: 22 } }
  ];

  SW.seed = {
    users: USERS, endpoints: ENDPOINTS, events: EVENTS, incidents: INCIDENTS,
    stages: STAGES, docs: SEED_DOCS, trendDays: TREND_DAYS, trendSeed: TREND_SEED,
    liveAlerts: LIVE_ALERTS
  };
})();
