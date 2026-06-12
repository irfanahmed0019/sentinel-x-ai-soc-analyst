import { ThreatCategory } from "./types";

export const CATEGORY_LABELS: Record<ThreatCategory, { label: string; color: string; bg: string }> = {
  critical: { label: "Critical Threat", color: "#dc2626", bg: "bg-red-50 text-red-700 border-red-200" },
  likely_threat: { label: "High Threat", color: "#f97316", bg: "bg-orange-50 text-orange-700 border-orange-200" },
  suspicious: { label: "Medium Anomaly", color: "#eab308", bg: "bg-yellow-50 text-yellow-800 border-yellow-200" },
  safe: { label: "Low / Benign", color: "#16a34a", bg: "bg-green-50 text-green-700 border-green-200" },
};

export const ATTACK_LABELS: Record<string, string> = {
  DDoS: "Distributed Denial of Service (DDoS)",
  "DoS Hulk": "Denial of Service (DoS) Hulk",
  "DoS GoldenEye": "Denial of Service (DoS) GoldenEye",
  "DoS slowloris": "Denial of Service (DoS) Slowloris",
  PortScan: "Port Scan / Service Discovery",
  "SSH-Patator": "SSH Brute Force Attack",
  "FTP-Patator": "FTP Brute Force Attack",
  Bot: "Botnet Communication / C2",
  "Web Attack - Brute Force": "Web Brute Force Attack",
  "Web Attack - XSS": "Cross-Site Scripting (XSS) Attack",
  "Web Attack - Sql Injection": "SQL Injection (SQLi) Attack",
  Infiltration: "Remote Service Infiltration",
  Heartbleed: "Heartbleed Vulnerability Exploit",
  BENIGN: "Benign Network Traffic",
};
