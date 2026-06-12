import socket
import asyncio
from datetime import datetime
from pydantic import BaseModel

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP"
}

class PortFinding(BaseModel):
    port: int
    service: str
    label: str

class ScanResponse(BaseModel):
    target: str
    ip_address: str
    open_ports: list[PortFinding]
    findings: list[str]
    risk_score: int
    severity: str
    attack_surface: str
    executive_summary: str
    error: str | None = None
    vulnerability_report: str | None = None

def _check_port(ip: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False

def generate_scan_static_report(
    target: str,
    ip_address: str,
    open_ports: list[PortFinding],
    findings: list[str],
    risk_score: int,
    severity: str
) -> str:
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    ports_table = ""
    if open_ports:
        ports_table += "| PORT | SERVICE | STATUS | RISK LEVEL |\n|------|---------|--------|------------|\n"
        for p in open_ports:
            port_risk = "Low"
            if p.port in (21, 23, 445):
                port_risk = "High"
            elif p.port in (80, 3306, 3389):
                port_risk = "Medium"
            ports_table += f"| {p.port}/tcp | {p.service} | OPEN | {port_risk} |\n"
    else:
        ports_table = "No common open ports detected."
        
    findings_list = ""
    if findings:
        for f in findings:
            findings_list += f"- ⚠️ {f}\n"
    else:
        findings_list = "- ✔ No critical security findings or policy violations detected."
        
    remediations = ""
    remediations_list = []
    if not open_ports:
        remediations_list.append("Maintain current firewall configurations. Continue routine scanning.")
    else:
        port_nums = [p.port for p in open_ports]
        if 21 in port_nums:
            remediations_list.append("Disable FTP (port 21) and migrate to SFTP (SSH File Transfer Protocol) or FTPS (FTP over SSL) to enforce encryption.")
        if 23 in port_nums:
            remediations_list.append("Decommission Telnet (port 23) immediately. Replace it with SSH for all remote command-line management.")
        if 80 in port_nums:
            remediations_list.append("Configure redirect rules from HTTP (port 80) to HTTPS (port 443). Enforce HSTS (HTTP Strict Transport Security) header policies.")
        if 445 in port_nums:
            remediations_list.append("Block SMB (port 445) at the internet perimeter. If SMB sharing is required externally, enforce access over IPSec VPN or utilize SMBv3 with encryption.")
        if 3306 in port_nums:
            remediations_list.append("Restrict MySQL database port (3306) to localhost or whitelist specific internal IPs. Enable transport layer encryption.")
        if 3389 in port_nums:
            remediations_list.append("Disable public RDP exposure (port 3389). Require MFA and an enterprise VPN / Bastion host for remote administrative access.")
        
        if len(open_ports) > 0:
            remediations_list.append("Implement ingress network ACLs on the firewall to permit traffic only for business-essential services.")
            remediations_list.append("Enable detailed audit logging for connection requests on the operating system level.")
            
    for idx, r in enumerate(remediations_list, start=1):
        remediations += f"{idx}. {r}\n"
        
    if severity == "CRITICAL" or severity == "HIGH":
        business_impact = "High Risk. The target exhibits critical port exposures that could lead to credentials theft, data exfiltration, or unauthorized administrative access. Immediate remediation is strongly advised."
    elif severity == "MEDIUM":
        business_impact = "Medium Risk. Moderate exposure exists. Although no direct high-impact command execution service is exposed without some protection, communication channels are unencrypted. Mitigation should be scheduled in the next maintenance window."
    else:
        business_impact = "Low Risk. The service exposure is minimal. No immediate threat to business operations is identified. Maintain regular scanning schedules."

    report = f"""# SENTINEL-X VULNERABILITY ASSESSMENT REPORT

## 1. EXECUTIVE SUMMARY
A network scan and security assessment was conducted against target host **{target}** (resolved IP: `{ip_address}`) at {timestamp}. 
The scan assessed vulnerability indicators on common protocols, yielding a cumulative risk score of **{risk_score}/100**, which falls under the **{severity}** severity tier.

- **Target Host**: `{target}`
- **Resolved IP**: `{ip_address}`
- **Assessed Severity**: `{severity}`
- **Exposed Service Ports**: {len(open_ports)}

---

## 2. TECHNICAL FINDINGS & PORT ANALYSIS
The table below lists all ports identified as open during the TCP handshake audit.

{ports_table}

### Identified Security Findings:
{findings_list}

---

## 3. RECOMMENDATIONS & HARDENING MITIGATIONS
Based on the identified service risks, the security operations team recommends implementing the following hardening measures:

{remediations}

---

## 4. BUSINESS RISK ASSESSMENT
**Operational Risk Impact**: {business_impact}

---
**CONFIDENTIALITY NOTICE**: This document contains proprietary security audit metrics. Distribution must be restricted to authorized IT Security and SOC operations personnel only.
"""
    return report

async def run_scan(
    target: str,
    ai_provider: str = "none",
    gemini_api_key: str | None = None,
    ollama_model: str | None = None,
    ollama_base_url: str = "http://localhost:11434"
) -> ScanResponse:
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        target_ip = socket.gethostbyname(clean_target)
    except socket.gaierror:
        return ScanResponse(
            target=target,
            ip_address="",
            open_ports=[],
            findings=[],
            risk_score=0,
            severity="LOW",
            attack_surface="Unknown",
            executive_summary="",
            error="Unable to resolve the target. Please enter a valid domain or IP address.",
            vulnerability_report=None
        )

    loop = asyncio.get_running_loop()
    tasks = []
    for port in COMMON_PORTS:
        tasks.append(loop.run_in_executor(None, _check_port, target_ip, port))
    
    results = await asyncio.gather(*tasks)
    
    open_ports = []
    port_numbers = []
    for (port, service), is_open in zip(COMMON_PORTS.items(), results):
        if is_open:
            open_ports.append(PortFinding(port=port, service=service, label=f"{port}/tcp {service}"))
            port_numbers.append(port)

    findings = []
    risk_score = 0
    # Baseline risk: each detected open port adds 5 points to risk score
    for _ in port_numbers:
        risk_score += 5

    if 21 in port_numbers:
        findings.append("FTP service detected. Cleartext file transfers expose credentials in transit. Migrate to SFTP or FTPS.")
        risk_score += 20
    if 23 in port_numbers:
        findings.append("Telnet service detected. Authentication credentials are transmitted in plaintext. Decommission immediately.")
        risk_score += 30
    if 80 in port_numbers and 443 not in port_numbers:
        findings.append("Unencrypted HTTP service detected without HTTPS. All traffic is observable in cleartext.")
    if 445 in port_numbers:
        findings.append("SMB port publicly reachable. High-risk exposure — restrict to private networks or disable externally.")
        risk_score += 25
    if 3306 in port_numbers:
        findings.append("MySQL database port publicly exposed. Unauthorised access risk is critical. Restrict to localhost or VPN.")
        risk_score += 20
    if 3389 in port_numbers:
        findings.append("RDP service publicly reachable. Brute-force and ransomware risk is high. Require VPN + MFA for access.")
        risk_score += 15

    total_open = len(open_ports)
    if total_open > 10:
        risk_score += 10
        findings.append(f"Excessive port exposure ({total_open} open ports). Significantly increases the external attack surface.")
    elif total_open > 5:
        risk_score += 5
        findings.append(f"Moderate port exposure ({total_open} open ports). Review necessity of each exposed service.")

    if risk_score >= 90:
        severity = "CRITICAL"
    elif risk_score >= 70:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if total_open > 8:
        attack_surface = "High"
    elif total_open > 3:
        attack_surface = "Medium"
    else:
        attack_surface = "Low"

    if total_open == 0:
        exec_summary = (
            f"External exposure assessment of {clean_target} detected no publicly reachable services. "
            f"No misconfigurations were identified. Overall exposure level is MINIMAL."
        )
    else:
        services = [p.service for p in open_ports]
        services_str = ", ".join(services[:3])
        extra = f" and {len(services) - 3} others" if len(services) > 3 else ""
        critical_flags = [f for f in findings if any(w in f for w in ["Telnet", "FTP", "RDP", "SMB", "MySQL"])]
        misconfig_note = (
            f"{len(critical_flags)} critical misconfiguration(s) detected requiring immediate attention."
            if critical_flags else "No critical misconfigurations were detected."
        )
        exec_summary = (
            f"External exposure assessment identified {total_open} publicly reachable service(s) "
            f"({services_str}{extra}) on {clean_target}. "
            f"{misconfig_note} "
            f"Overall exposure level is {severity}."
        )

    vulnerability_report = None
    if ai_provider in ("gemini", "ollama"):
        try:
            ports_str = ", ".join([f"{p.port} ({p.service})" for p in open_ports]) if open_ports else "None detected"
            findings_str = "\n".join([f"- {f}" for f in findings]) if findings else "None detected"
            prompt = f"""You are a senior SOC analyst. Generate a detailed, professional vulnerability assessment report for target '{clean_target}' ({target_ip}).
Scan Results:
- Open Ports: {ports_str}
- Key Findings: {findings_str}
- Risk Score: {risk_score}/100
- Severity: {severity}

Format the report inside a plain text block using standard markdown style, with these exact section headers:
1. EXECUTIVE SUMMARY
2. TECHNICAL FINDINGS & PORT ANALYSIS
3. RECOMMENDATIONS & HARDENING MITIGATIONS
4. BUSINESS RISK ASSESSMENT

Keep it realistic, highly detailed, and professional. Avoid placeholders."""

            if ai_provider == "gemini" and gemini_api_key:
                from gemini_client import call_gemini
                vulnerability_report = await loop.run_in_executor(None, call_gemini, prompt, gemini_api_key)
            elif ai_provider == "ollama" and ollama_model:
                from ollama_client import call_ollama
                vulnerability_report = await loop.run_in_executor(None, call_ollama, prompt, ollama_model, ollama_base_url)
            else:
                vulnerability_report = generate_scan_static_report(clean_target, target_ip, open_ports, findings, risk_score, severity)
        except Exception as e:
            vulnerability_report = f"⚠️ AI Report generation failed ({str(e)}). Falling back to static report.\n\n" + \
                                   generate_scan_static_report(clean_target, target_ip, open_ports, findings, risk_score, severity)
    else:
        vulnerability_report = generate_scan_static_report(clean_target, target_ip, open_ports, findings, risk_score, severity)

    return ScanResponse(
        target=clean_target,
        ip_address=target_ip,
        open_ports=open_ports,
        findings=findings,
        risk_score=risk_score,
        severity=severity,
        attack_surface=attack_surface,
        executive_summary=exec_summary,
        vulnerability_report=vulnerability_report
    )
