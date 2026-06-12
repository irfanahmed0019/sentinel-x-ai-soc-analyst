import axios from "axios";
import jsPDF from "jspdf";
import {
  Activity,
  Bot,
  Brain,
  ChartBar,
  Download,
  FileText,
  Filter,
  HardDrive,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Target,
  UploadCloud,
  Zap,
} from "lucide-react";
import html2canvas from "html2canvas";
import { useEffect, useMemo, useRef, useState } from "react";
import { FixedSizeList, ListChildComponentProps } from "react-window";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { CATEGORY_LABELS } from "./threatLabels";
import { AiProvider, ProgressEvent, Report, ThreatCategory, ThreatRow } from "./types";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL ??
  "https://sentinel-x-ai-soc-analyst-production.up.railway.app";

function formatNumber(value: number | undefined) {
  return typeof value === "number" ? value.toLocaleString() : "0";
}

// Simple filter helper
function applyFilters(threats: ThreatRow[], filters: {severity?: string; src?: string; dst?: string}) {
  return threats.filter(t => {
    if (filters.severity && t.severity !== filters.severity) return false;
    if (filters.src && !t.src_ip.includes(filters.src)) return false;
    if (filters.dst && !t.dst_ip.includes(filters.dst)) return false;
    return true;
  });
}

function formatBytes(value: number) {
  if (value < 1024 * 1024) return `${Math.max(1, Math.round(value / 1024))} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

interface PortFinding {
  port: number;
  service: string;
  label: string;
}

interface ScanResponse {
  target: string;
  ip_address: string;
  open_ports: PortFinding[];
  findings: string[];
  risk_score: number;
  severity: string;
  attack_surface: string;
  executive_summary: string;
  error?: string;
  vulnerability_report?: string;
}

export default function App() {
  const [file, setFile] = useState<File | null>(null);
  const [provider, setProvider] = useState<AiProvider>("gemini");
  const [geminiKey, setGeminiKey] = useState("");
  const [ollamaModel, setOllamaModel] = useState("llama3");
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"threat" | "scan">("threat");
  const reportRef = useRef<HTMLDivElement>(null);
  const [filters, setFilters] = useState<{severity?: string; src?: string; dst?: string}>({});
  useEffect(() => {
  console.log("API_BASE =", API_BASE);
}, []);
  
  async function startAnalysis() {
    if (!file) {
      setError("Choose a CSV file first.");
      return;
    }
    if (file.size > 2 * 1024 * 1024 * 1024) {
      setError("This CSV is larger than 2GB. Split it first or raise MAX_UPLOAD_MB in the backend.");
      return;
    }
    if (provider === "gemini" && !geminiKey.trim()) {
      setError("Enter your Gemini API key, or switch to Ollama for local AI analysis.");
      return;
    }
    if (provider === "ollama" && !ollamaModel.trim()) {
      setError("Enter an Ollama model name, for example llama3.");
      return;
    }
    setError("");
    setReport(null);
    setProgress({ stage: "upload", percent: 1, message: `Preparing ${formatBytes(file.size)} CSV upload...` });

    const form = new FormData();
    form.append("file", file);
    form.append("ai_provider", provider);
    if (provider === "gemini") form.append("gemini_api_key", geminiKey);
    if (provider === "ollama") form.append("ollama_model", ollamaModel);

    try {
      const upload = await axios.post(`${API_BASE}/api/upload`, form, {
        timeout: 0,
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
        onUploadProgress: (event) => {
          if (!event.total) {
            setProgress({ stage: "upload", percent: 3, message: `Uploading ${formatBytes(file.size)} CSV...` });
            return;
          }
          const uploadPercent = Math.min(14, Math.max(1, Math.round((event.loaded / event.total) * 14)));
          setProgress({
            stage: "upload",
            percent: uploadPercent,
            message: `Uploading ${formatBytes(event.loaded)} of ${formatBytes(event.total)}...`,
          });
        },
      });
      setProgress({ stage: "upload", percent: 15, message: "Upload complete. Starting SENTINEL-X analysis..." });
      const jobId = upload.data.job_id;
      const source = new EventSource(`${API_BASE}/api/progress/${jobId}`);
      source.onmessage = async (event) => {
        const next = JSON.parse(event.data) as ProgressEvent;
        setProgress(next);
        if (next.stage === "done") {
          source.close();
          const response = await axios.get<Report>(`${API_BASE}/api/report/${jobId}`, { timeout: 0 });
          setReport(response.data);
        }
        if (next.stage === "error") {
          source.close();
          setError(next.message);
        }
      };
      source.onerror = () => {
        source.close();
        setError("Progress connection lost. Check the backend and try again.");
      };
    } catch (reason) {
      const message = axios.isAxiosError(reason)
        ? reason.response?.data?.detail || reason.message
        : "Upload failed. Check that the backend is running.";
      setProgress({ stage: "error", percent: -1, message });
      setError(String(message));
    }
  }
  const [isExporting, setIsExporting] = useState(false);

  async function exportPdf() {
    if (!report) return;
    try {
      setIsExporting(true);
      await new Promise(resolve => setTimeout(resolve, 50));

      const pdf = new jsPDF("p", "mm", "a4");
      const W = pdf.internal.pageSize.getWidth();
      const H = pdf.internal.pageSize.getHeight();
      const M = 15; // margin
      const CW = W - 2 * M; // content width
      let y = 0;

      const maxRisk = report.ml.top_threats.length > 0 ? report.ml.top_threats[0].danger_score : 0;
      let campaignSev = "UNKNOWN";
      if (maxRisk >= 90) campaignSev = "CRITICAL";
      else if (maxRisk >= 70) campaignSev = "HIGH";
      else if (maxRisk >= 40) campaignSev = "MEDIUM";
      else if (maxRisk > 0) campaignSev = "LOW";

      const sevColor: Record<string, [number, number, number]> = {
        CRITICAL: [220, 38, 38], HIGH: [249, 115, 22], MEDIUM: [234, 179, 8], LOW: [34, 197, 94], UNKNOWN: [100, 116, 139],
      };
      const brandColor: [number, number, number] = [226, 75, 74];
      const darkBg: [number, number, number] = [15, 23, 42];
      const white: [number, number, number] = [255, 255, 255];
      const gray: [number, number, number] = [100, 116, 139];
      const lightBg: [number, number, number] = [248, 250, 252];
      const borderGray: [number, number, number] = [226, 232, 240];

      function addFooter(pageNum: number) {
        pdf.setFontSize(8);
        pdf.setTextColor(...gray);
        pdf.text(`SENTINEL-X  ·  Confidential SOC Report  ·  ${report!.file_name}`, M, H - 8);
        pdf.text(`Page ${pageNum}`, W - M, H - 8, { align: "right" });
        pdf.setDrawColor(...borderGray);
        pdf.line(M, H - 12, W - M, H - 12);
      }

      function checkPage(needed: number): number {
        if (y + needed > H - 18) {
          addFooter(pdf.getNumberOfPages());
          pdf.addPage();
          y = M;
        }
        return y;
      }

      function sectionTitle(title: string, color: [number, number, number] = brandColor) {
        y = checkPage(16);
        pdf.setFillColor(...color);
        pdf.roundedRect(M, y, CW, 10, 1.5, 1.5, "F");
        pdf.setFont("helvetica", "bold");
        pdf.setFontSize(11);
        pdf.setTextColor(...white);
        pdf.text(title.toUpperCase(), M + 4, y + 7);
        y += 14;
      }

      function bodyText(text: string, opts?: { bold?: boolean; size?: number; color?: [number, number, number]; indent?: number }) {
        const sz = opts?.size || 9;
        const indent = opts?.indent || 0;
        pdf.setFont("helvetica", opts?.bold ? "bold" : "normal");
        pdf.setFontSize(sz);
        pdf.setTextColor(...(opts?.color || [30, 41, 59]));
        const lines = pdf.splitTextToSize(text, CW - indent);
        for (const line of lines) {
          y = checkPage(5);
          pdf.text(line, M + indent, y);
          y += sz * 0.45;
        }
        y += 2;
      }

      function kpiRow(items: Array<{ label: string; value: string; color?: [number, number, number] }>) {
        y = checkPage(22);
        const cardW = (CW - (items.length - 1) * 3) / items.length;
        items.forEach((item, i) => {
          const x = M + i * (cardW + 3);
          pdf.setFillColor(...lightBg);
          pdf.setDrawColor(...borderGray);
          pdf.roundedRect(x, y, cardW, 18, 1.5, 1.5, "FD");
          pdf.setFont("helvetica", "normal");
          pdf.setFontSize(7);
          pdf.setTextColor(...gray);
          pdf.text(item.label.toUpperCase(), x + 3, y + 6);
          pdf.setFont("helvetica", "bold");
          pdf.setFontSize(13);
          pdf.setTextColor(...(item.color || [30, 41, 59]));
          pdf.text(item.value, x + 3, y + 14);
        });
        y += 22;
      }

      function tableHeader(cols: Array<{ label: string; width: number }>) {
        y = checkPage(10);
        pdf.setFillColor(...darkBg);
        let x = M;
        const rowH = 8;
        cols.forEach(c => { pdf.rect(x, y, c.width, rowH, "F"); x += c.width; });
        x = M;
        pdf.setFont("helvetica", "bold");
        pdf.setFontSize(7);
        pdf.setTextColor(...white);
        cols.forEach(c => { pdf.text(c.label, x + 2, y + 5.5); x += c.width; });
        y += rowH;
      }

      function tableRow(cols: Array<{ text: string; width: number; color?: [number, number, number] }>, bg: [number, number, number]) {
        y = checkPage(8);
        pdf.setFillColor(...bg);
        let x = M;
        const rowH = 7;
        cols.forEach(c => { pdf.rect(x, y, c.width, rowH, "F"); x += c.width; });
        x = M;
        pdf.setFont("helvetica", "normal");
        pdf.setFontSize(7);
        cols.forEach(c => {
          pdf.setTextColor(...(c.color || [30, 41, 59]));
          const maxWidth = c.width - 4;
          const lines = pdf.splitTextToSize(c.text, maxWidth);
          let display = lines[0] || "";
          // If text was truncated, add ellipsis
          if (lines.length > 1 || pdf.getTextWidth(display) > maxWidth) {
            while (display.length > 0 && pdf.getTextWidth(display + "…") > maxWidth) {
              display = display.slice(0, -1);
            }
            display = display.trimEnd() + "…";
          }
          pdf.text(display, x + 2, y + 5);
          x += c.width;
        });
        y += rowH;
      }

      // ═══════════════════════════════════════════════════════════
      // PAGE 1: COVER
      // ═══════════════════════════════════════════════════════════
      pdf.setFillColor(...darkBg);
      pdf.rect(0, 0, W, H, "F");

      // Brand logo area
      pdf.setFillColor(...brandColor);
      pdf.roundedRect(W / 2 - 18, 55, 36, 36, 5, 5, "F");
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(22);
      pdf.setTextColor(...white);
      pdf.text("S-X", W / 2, 78, { align: "center" });

      pdf.setFontSize(32);
      pdf.setTextColor(...white);
      pdf.text("SENTINEL-X", W / 2, 110, { align: "center" });

      pdf.setFontSize(14);
      pdf.setTextColor(...gray);
      pdf.text("SOC Threat Intelligence Report", W / 2, 120, { align: "center" });

      // Campaign severity badge
      const sc = sevColor[campaignSev] || gray;
      pdf.setFillColor(...sc);
      pdf.roundedRect(W / 2 - 30, 135, 60, 12, 2, 2, "F");
      pdf.setFontSize(11);
      pdf.setTextColor(...white);
      pdf.text(`CAMPAIGN: ${campaignSev}`, W / 2, 143, { align: "center" });

      // Metadata
      pdf.setFontSize(10);
      pdf.setTextColor(...gray);
      const meta = [
        `File: ${report.file_name}`,
        `Records Analyzed: ${formatNumber(report.summary.total_records)}`,
        `Generated: ${new Date(report.processed_at).toLocaleString()}`,
        `Pipeline Duration: ${report.pipeline_duration_seconds}s`,
        `AI Provider: ${report.ai_provider_used === "gemini" ? "Google Gemini Flash" : report.ai_provider_used === "ollama" ? "Ollama Local" : "None"}`,
      ];
      let metaY = 160;
      meta.forEach(line => { pdf.text(line, W / 2, metaY, { align: "center" }); metaY += 7; });

      pdf.setFontSize(8);
      pdf.setTextColor(80, 80, 80);
      pdf.text("CONFIDENTIAL — Authorized Personnel Only", W / 2, H - 20, { align: "center" });
      addFooter(1);

      // ═══════════════════════════════════════════════════════════
      // PAGE 2: EXECUTIVE DASHBOARD
      // ═══════════════════════════════════════════════════════════
      pdf.addPage();
      y = M;

      sectionTitle("Executive Dashboard");

      kpiRow([
        { label: "Total Records", value: formatNumber(report.summary.total_records) },
        { label: "Medium Risk", value: formatNumber(report.summary.suspicious_count), color: [234, 179, 8] },
        { label: "High Risk", value: formatNumber(report.summary.likely_threat_count), color: [249, 115, 22] },
        { label: "Campaign Severity", value: campaignSev, color: sc },
      ]);

      kpiRow([
        { label: "Highest Risk Score", value: maxRisk ? String(Math.round(maxRisk)) : "N/A", color: [220, 38, 38] },
        { label: "Most Common Attack", value: report.summary.most_common_attack || "N/A" },
        { label: "Threat Rate", value: `${report.summary.threat_percentage}%`, color: [249, 115, 22] },
        { label: "AI Provider", value: report.ai_provider_used === "gemini" ? "Gemini Flash" : report.ai_provider_used },
      ]);

      // Pipeline Summary
      sectionTitle("Pipeline Summary");
      const uniqueSources = new Set(report.ml.top_threats.map(t => t.src_ip)).size;
      const targetPort = report.ml.top_threats.length > 0 ? report.ml.top_threats[0].dst_port : 80;
      const mostCommon = report.summary.most_common_attack || "suspicious";
      let summaryText = `Analysis of ${formatNumber(report.summary.total_records)} network flows detected a coordinated ${mostCommon} campaign originating from ${uniqueSources} primary sources targeting services on port ${targetPort}. `;
      summaryText += `Highest risk score observed was ${Math.round(maxRisk)}. Campaign severity is assessed as ${campaignSev}.`;
      bodyText(summaryText, { size: 10 });

      // ML Performance
      if (report.ml.supervised_available) {
        sectionTitle("ML Model Performance");
        const fmtPct = (v: number | null | undefined) => v ? `${(v * 100).toFixed(2)}%` : "N/A";
        kpiRow([
          { label: "Accuracy", value: fmtPct(report.ml.model_accuracy) },
          { label: "Precision", value: fmtPct(report.ml.model_precision) },
          { label: "Recall", value: fmtPct(report.ml.model_recall) },
          { label: "F1 Score", value: fmtPct(report.ml.model_f1) },
        ]);
        bodyText("Model: Random Forest Classifier (n_estimators=100, max_depth=20, class_weight=balanced). Anomaly detection: Isolation Forest (contamination=0.02). Confidence values are derived from Random Forest class probabilities.", { size: 8, color: gray });
      }

      addFooter(pdf.getNumberOfPages());

      // ═══════════════════════════════════════════════════════════
      // PAGE 3: AI ANALYST REPORT
      // ═══════════════════════════════════════════════════════════
      pdf.addPage();
      y = M;

      const ai = report.ai_analysis;
      if (ai && !ai.error) {
        sectionTitle("AI Analyst Report", [59, 130, 246]);

        if (ai.executive_summary || ai.what_is_happening) {
          bodyText("Executive Summary", { bold: true, size: 10 });
          bodyText(ai.executive_summary || ai.what_is_happening || "", { size: 9 });
        }

        if (ai.attack_types) {
          y += 2;
          bodyText("Attack Types Observed", { bold: true, size: 10 });
          bodyText(ai.attack_types, { size: 9 });
        }

        if (ai.severity_assessment) {
          y += 2;
          bodyText("Severity Assessment", { bold: true, size: 10 });
          bodyText(ai.severity_assessment, { size: 9 });
        }

        if (ai.indicators_of_compromise) {
          y += 2;
          bodyText("Indicators of Compromise", { bold: true, size: 10 });
          bodyText(ai.indicators_of_compromise, { size: 9 });
        }

        if (ai.mitre_attack_techniques) {
          y += 2;
          bodyText("MITRE ATT&CK Mapping", { bold: true, size: 10 });
          bodyText(ai.mitre_attack_techniques, { size: 9 });
        }

        const actions = Array.isArray(ai.recommended_immediate_actions) ? ai.recommended_immediate_actions as string[] : [];
        if (actions.length > 0) {
          y += 2;
          sectionTitle("Immediate Actions Required", [220, 38, 38]);
          actions.forEach((a, i) => { bodyText(`${i + 1}. ${a}`, { size: 9, indent: 3 }); });
        }

        const longTerm = Array.isArray(ai.long_term_mitigations) ? ai.long_term_mitigations as string[] : [];
        if (longTerm.length > 0) {
          y += 2;
          sectionTitle("Long-Term Mitigations", [59, 130, 246]);
          longTerm.forEach((m, i) => { bodyText(`${i + 1}. ${m}`, { size: 9, indent: 3 }); });
        }

        if (ai.business_impact_assessment) {
          y += 2;
          sectionTitle("Business Impact Assessment", [100, 116, 139]);
          bodyText(ai.business_impact_assessment, { size: 9 });
        }
      } else {
        sectionTitle("AI Analyst Report");
        bodyText("AI analysis was not enabled for this run. Enable Gemini or Ollama for a full AI-powered SOC report.", { size: 10, color: gray });
      }

      addFooter(pdf.getNumberOfPages());

      // ═══════════════════════════════════════════════════════════
      // PAGE 4+: TOP THREATS TABLE
      // ═══════════════════════════════════════════════════════════
      pdf.addPage();
      y = M;

      sectionTitle("Top Threat Events (Detailed)");

      const threats = report.ml.top_threats;
      const colDefs = [
        { label: "#", width: 8 },
        { label: "SOURCE IP", width: 28 },
        { label: "DEST IP", width: 28 },
        { label: "PORT", width: 14 },
        { label: "TYPE", width: 26 },
        { label: "RISK", width: 14 },
        { label: "SEVERITY", width: 18 },
        { label: "CONFIDENCE", width: 20 },
        { label: "MITRE TECHNIQUE", width: CW - 8 - 28 - 28 - 14 - 26 - 14 - 18 - 20 },
      ];

      tableHeader(colDefs);

      threats.forEach((t, i) => {
        const sevC = t.severity === "Critical" ? sevColor.CRITICAL : t.severity === "High" ? sevColor.HIGH : t.severity === "Medium" ? sevColor.MEDIUM : gray;
        const bg: [number, number, number] = i % 2 === 0 ? [255, 255, 255] : lightBg;
        tableRow([
          { text: String(t.rank || i + 1), width: colDefs[0].width },
          { text: t.src_ip, width: colDefs[1].width },
          { text: t.dst_ip, width: colDefs[2].width },
          { text: String(t.dst_port), width: colDefs[3].width },
          { text: t.threat_type, width: colDefs[4].width },
          { text: String(Math.round(t.danger_score)), width: colDefs[5].width, color: sevC },
          { text: t.severity, width: colDefs[6].width, color: sevC },
          { text: `${(t.rf_confidence * 100).toFixed(1)}%`, width: colDefs[7].width },
          { text: t.mitre_id ? `${t.mitre_id} ${t.mitre_technique || ""}` : "N/A", width: colDefs[8].width },
        ], bg);
      });

      y += 4;
      bodyText(`Showing ${threats.length} highest-risk events sorted by danger score. Confidence is derived from Random Forest class probability.`, { size: 7, color: gray });

      addFooter(pdf.getNumberOfPages());

      // ═══════════════════════════════════════════════════════════
      // PAGE 5+: NETWORK INTELLIGENCE
      // ═══════════════════════════════════════════════════════════
      pdf.addPage();
      y = M;

      sectionTitle("Network Intelligence");

      // Top Source IPs
      bodyText("Top Source IPs by Volume", { bold: true, size: 10 });
      y += 2;
      const ipColDefs = [
        { label: "SOURCE IP", width: CW * 0.5 },
        { label: "REQUESTS", width: CW * 0.5 },
      ];
      tableHeader(ipColDefs);
      (report.eda.top_source_ips || []).slice(0, 15).forEach((ip, i) => {
        tableRow([
          { text: ip.ip, width: ipColDefs[0].width },
          { text: formatNumber(ip.count), width: ipColDefs[1].width },
        ], i % 2 === 0 ? white : lightBg);
      });

      y += 6;

      // Top Destination Ports
      bodyText("Top Destination Ports", { bold: true, size: 10 });
      y += 2;
      const portColDefs = [
        { label: "PORT", width: CW * 0.5 },
        { label: "CONNECTIONS", width: CW * 0.5 },
      ];
      tableHeader(portColDefs);
      (report.eda.top_dest_ports || []).slice(0, 10).forEach((p, i) => {
        tableRow([
          { text: String(p.port), width: portColDefs[0].width },
          { text: formatNumber(p.count), width: portColDefs[1].width },
        ], i % 2 === 0 ? white : lightBg);
      });

      y += 6;

      // Protocol Distribution
      if (report.eda.protocol_split) {
        bodyText("Protocol Distribution", { bold: true, size: 10 });
        y += 2;
        const protoColDefs = [
          { label: "PROTOCOL", width: CW * 0.5 },
          { label: "COUNT", width: CW * 0.5 },
        ];
        tableHeader(protoColDefs);
        Object.entries(report.eda.protocol_split).slice(0, 10).forEach(([proto, cnt], i) => {
          tableRow([
            { text: proto, width: protoColDefs[0].width },
            { text: formatNumber(cnt as number), width: protoColDefs[1].width },
          ], i % 2 === 0 ? white : lightBg);
        });
      }

      y += 6;

      // Label Distribution
      if (report.eda.label_distribution) {
        bodyText("Attack Label Distribution", { bold: true, size: 10 });
        y += 2;
        const lblColDefs = [
          { label: "LABEL", width: CW * 0.5 },
          { label: "COUNT", width: CW * 0.5 },
        ];
        tableHeader(lblColDefs);
        Object.entries(report.eda.label_distribution).sort((a, b) => (b[1] as number) - (a[1] as number)).slice(0, 15).forEach(([lbl, cnt], i) => {
          tableRow([
            { text: lbl, width: lblColDefs[0].width },
            { text: formatNumber(cnt as number), width: lblColDefs[1].width },
          ], i % 2 === 0 ? white : lightBg);
        });
      }

      addFooter(pdf.getNumberOfPages());

      // ═══════════════════════════════════════════════════════════
      // LAST PAGE: DISCLAIMER
      // ═══════════════════════════════════════════════════════════
      pdf.addPage();
      y = M;

      sectionTitle("Report Disclaimer & Methodology", [100, 116, 139]);
      bodyText("This report was generated by SENTINEL-X, an automated SOC threat intelligence platform. The ML pipeline uses Isolation Forest for unsupervised anomaly detection and Random Forest for supervised threat classification. Risk scores are computed using a weighted ensemble of anomaly scores and classification confidence.", { size: 9 });
      y += 2;
      bodyText("The AI analyst report (if enabled) is generated by a Large Language Model and should be reviewed by a human analyst before taking action. SENTINEL-X does not guarantee the accuracy of AI-generated recommendations.", { size: 9 });
      y += 2;
      bodyText("Threat intelligence enrichment is based on publicly available data and may not reflect the most current threat landscape. All IP addresses, ports, and protocols referenced in this report are derived from the uploaded dataset.", { size: 9 });
      y += 6;
      bodyText(`Report ID: ${report.job_id}`, { size: 8, color: gray });
      bodyText(`Generated: ${new Date().toISOString()}`, { size: 8, color: gray });
      bodyText("Classification: CONFIDENTIAL", { size: 8, color: gray });

      addFooter(pdf.getNumberOfPages());

      pdf.save(`SENTINEL-X-SOC-Report-${report.job_id.slice(0, 8)}.pdf`);
    } catch (e) {
      console.error("PDF Export failed:", e);
      alert("Failed to export PDF.");
    } finally {
      setIsExporting(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#f4f6f8] text-ink">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#e24b4a] text-white">
              <ShieldCheck size={22} />
            </div>
            <div>
              <h1 className="text-xl font-black tracking-normal">SENTINEL-X</h1>
              <p className="text-xs text-steel">SOC Analyst Dashboard · Powered by {provider === "gemini" ? "Gemini" : "Ollama"}</p>
            </div>
          </div>
          <div className="hidden items-center gap-3 sm:flex">
            <span className="rounded-full border border-green-200 bg-green-50 px-3 py-1 text-xs font-semibold text-green-700">Live Analysis</span>
            <div className="flex items-center gap-2 rounded border border-slate-200 px-3 py-2 text-sm text-steel">
            <ShieldAlert size={18} />
            ML detects. AI explains.
            </div>
          </div>
        </div>
      </header>

      <div className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl px-4">
          <button
            className={`px-4 py-3 text-sm font-semibold border-b-2 ${activeTab === "threat" ? "border-[#e24b4a] text-ink" : "border-transparent text-steel hover:text-ink"}`}
            onClick={() => setActiveTab("threat")}
          >
            Threat Analysis
          </button>
          <button
            className={`px-4 py-3 text-sm font-semibold border-b-2 ${activeTab === "scan" ? "border-[#e24b4a] text-ink" : "border-transparent text-steel hover:text-ink"}`}
            onClick={() => setActiveTab("scan")}
          >
            Live Asset Scan
          </button>
        </div>
      </div>

      {activeTab === "threat" ? (
        <section className="mx-auto grid max-w-7xl gap-4 px-4 py-5 lg:grid-cols-[360px_1fr]">
          <UploadPanel
            file={file}
            setFile={setFile}
            provider={provider}
            setProvider={setProvider}
            geminiKey={geminiKey}
            setGeminiKey={setGeminiKey}
            ollamaModel={ollamaModel}
            setOllamaModel={setOllamaModel}
            onStart={startAnalysis}
            busy={Boolean(progress && !["done", "error"].includes(progress.stage))}
          />

          <div className="space-y-4">
            {error && <div className="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
            {!report && <PipelinePanel provider={provider} />}
            {progress && !report && <ProgressPanel progress={progress} />}
            {report ? <Dashboard report={report} onExport={exportPdf} reportRef={reportRef} isExporting={isExporting} /> : <EmptyState />}
          </div>
        </section>
      ) : (
        <LiveAssetScan provider={provider} geminiKey={geminiKey} ollamaModel={ollamaModel} />
      )}
    </main>
  );
}

function UploadPanel(props: {
  file: File | null;
  setFile: (file: File | null) => void;
  provider: AiProvider;
  setProvider: (provider: AiProvider) => void;
  geminiKey: string;
  setGeminiKey: (key: string) => void;
  ollamaModel: string;
  setOllamaModel: (model: string) => void;
  onStart: () => void;
  busy: boolean;
}) {
  return (
    <aside className="h-fit overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-bold uppercase text-steel">Upload CSV</h2>
      </div>
      <div className="p-4">
      <label className="flex min-h-52 cursor-pointer flex-col items-center justify-center rounded-md border border-dashed border-slate-300 bg-slate-50 px-4 text-center hover:bg-white hover:border-[#e24b4a]">
        <UploadCloud className="mb-3 text-[#e24b4a]" size={34} />
        <span className="text-sm font-semibold">{props.file ? props.file.name : "Drop network log CSV here"}</span>
        <span className="mt-1 text-xs text-steel">CICIDS2017 format · 1M+ rows via Polars + ML</span>
        <input type="file" accept=".csv" className="hidden" onChange={(event) => props.setFile(event.target.files?.[0] || null)} />
      </label>

      <div className="mt-4 grid grid-cols-3 rounded border border-slate-200 p-1 text-sm">
        {(["gemini", "ollama", "none"] as AiProvider[]).map((option) => (
          <button
            key={option}
            className={`rounded px-3 py-2 font-medium capitalize ${props.provider === option ? "bg-[#111827] text-white" : "text-steel hover:bg-slate-100"}`}
            onClick={() => props.setProvider(option)}
            type="button"
          >
            {option === "none" ? "No AI" : option}
          </button>
        ))}
      </div>

      {props.provider === "gemini" && (
        <input
          className="mt-3 w-full rounded border border-slate-300 px-3 py-2 text-sm"
          placeholder="Gemini API key"
          type="password"
          value={props.geminiKey}
          onChange={(event) => props.setGeminiKey(event.target.value)}
        />
      )}
      {props.provider === "ollama" && (
        <input
          className="mt-3 w-full rounded border border-slate-300 px-3 py-2 text-sm"
          placeholder="Ollama model"
          value={props.ollamaModel}
          onChange={(event) => props.setOllamaModel(event.target.value)}
        />
      )}

      <button
        className="mt-4 flex w-full items-center justify-center gap-2 rounded bg-signal px-4 py-3 font-semibold text-white hover:bg-teal-800 disabled:cursor-not-allowed disabled:bg-slate-400"
        onClick={props.onStart}
        disabled={props.busy}
        type="button"
      >
        <Activity size={18} />
        {props.provider === "none" ? "Analyze Local ML" : `Analyze With ${props.provider === "gemini" ? "Gemini" : "Ollama"}`}
      </button>
      <p className="mt-3 text-xs leading-5 text-steel">
        AI is used only for the final top-20 threat explanation. Detection still runs locally with Isolation Forest and Random Forest.
      </p>
      </div>
    </aside>


  );
}

function PipelinePanel({ provider }: { provider: AiProvider }) {
  const aiName = provider === "ollama" ? "Ollama Analyst" : "Gemini Analyst";
  return (
    <section className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="flex border-b border-slate-200">
        <div className="border-b-2 border-[#e24b4a] px-4 py-3 text-sm font-semibold">ML Pipeline</div>
        <div className="px-4 py-3 text-sm text-steel">Upload CSV</div>
      </div>
      <div className="grid md:grid-cols-3">
        <PipelineStep icon={<ChartBar size={17} />} state="done" kicker="Layer 01 · EDA" title="EDA Engine" text="Stats, IP frequency, port distribution, and traffic baselines." />
        <PipelineStep icon={<Brain size={17} />} state="done" kicker="Layer 02 · ML" title="ML Engine" text="Isolation Forest anomalies plus Random Forest threat labels." />
        <PipelineStep icon={<Bot size={17} />} state="active" kicker="Layer 03 · AI" title={aiName} text="Top 20 flagged records become a plain-English SOC report." />
      </div>
      <div className="flex flex-wrap gap-4 border-t border-slate-200 px-4 py-3 text-xs text-steel">
        <span><b className="text-ink">Backend:</b> FastAPI + scikit-learn + Polars</span>
        <span><b className="text-ink">Frontend:</b> React + TypeScript + Tailwind</span>
        <span><b className="text-ink">AI:</b> Gemini cloud or Ollama local</span>
      </div>
    </section>
  );
}

function PipelineStep({ icon, kicker, title, text, state }: { icon: React.ReactNode; kicker: string; title: string; text: string; state: "done" | "active" }) {
  return (
    <div className={`border-b border-slate-200 p-4 md:border-b-0 md:border-r ${state === "active" ? "bg-blue-50" : "bg-white"}`}>
      <p className="text-[10px] font-bold uppercase tracking-wide text-steel">{kicker}</p>
      <h3 className={`mt-1 flex items-center gap-2 text-sm font-bold ${state === "active" ? "text-blue-700" : "text-green-700"}`}>
        {icon}
        {title}
      </h3>
      <p className="mt-1 text-xs leading-5 text-steel">{text}</p>
    </div>
  );
}

function ProgressPanel({ progress }: { progress: ProgressEvent }) {
  const [displayPercent, setDisplayPercent] = useState(progress.percent);

  useEffect(() => {
    // Artificial smooth progression logic
    const interval = setInterval(() => {
      setDisplayPercent((prev) => {
        if (prev < progress.percent) {
          const diff = progress.percent - prev;
          const increment = diff > 10 ? 1.5 : Math.random() * 0.4 + 0.1;
          return Math.min(progress.percent, prev + increment);
        } else if (prev === progress.percent && prev < 100) {
          return Math.min(progress.percent + 9.99, prev + Math.random() * 0.05 + 0.01);
        }
        return prev;
      });
    }, 100);

    return () => clearInterval(interval);
  }, [progress.percent]);

  const codeSnippets: Record<string, string> = {
    "init": "import polars as pl\ndf = pl.read_csv('upload.csv')",
    "eda": "df.describe()\ntraffic = df.group_by('time_bucket').count()",
    "ml": "iso = IsolationForest(n_estimators=100, contamination=0.05)\niso.fit(sample_matrix)\nrf = RandomForestClassifier(n_estimators=100)",
    "ai": "threats_formatted = format_for_ai(top_threats)\nresponse = model.generate_content(threats_formatted)\nanalysis = parse_response(response)"
  };

  const currentCode = codeSnippets[progress.stage] || "";

  return (
    <section className="rounded border border-slate-200 bg-white shadow-sm overflow-hidden">
      <div className="p-5">
        <div className="flex items-center justify-between mb-3">
          <span className="font-semibold uppercase text-steel text-sm">{progress.stage.toUpperCase()}</span>
          <span className="font-mono text-sm font-bold">{Math.max(0, displayPercent).toFixed(2)}%</span>
        </div>
        <div className="h-3 overflow-hidden rounded bg-slate-100 mb-3">
          <div className="h-full bg-signal transition-all duration-200 ease-out" style={{ width: `${Math.max(0, displayPercent)}%` }} />
        </div>
        <p className="text-sm text-steel mb-3">{progress.message}</p>

        {/* Live Code Display */}
        {currentCode && (
          <div className="bg-slate-50 border border-slate-200 rounded p-3 mb-3">
            <p className="text-xs font-bold text-slate-500 mb-2 uppercase">🔄 Currently Running</p>
            <pre className="text-xs font-mono text-slate-700 overflow-auto max-h-24 whitespace-pre-wrap break-words">
              {currentCode}
            </pre>
          </div>
        )}
      </div>
    </section>
  );
}

function EmptyState() {
  return (
    <section className="flex min-h-72 items-center justify-center rounded-lg border border-slate-200 bg-white p-8 text-center shadow-sm">
      <div>
        <HardDrive className="mx-auto text-slate-400" size={44} />
        <h2 className="mt-3 text-lg font-bold">Waiting for live SOC analysis</h2>
        <p className="mt-2 max-w-lg text-sm text-steel">
          Upload a CSV to generate EDA, ML danger scores, top threats, charts, and an optional analyst explanation.
        </p>
      </div>
    </section>
  );
}

function Dashboard({ report, onExport, reportRef, isExporting }: { report: Report; onExport: () => void; reportRef: React.RefObject<HTMLDivElement>; isExporting: boolean }) {
  return (
    <div ref={reportRef} className="space-y-4">
      <section className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white p-4 shadow-sm" data-html2canvas-ignore>
        <div>
          <h2 className="text-xl font-black text-slate-800">Analysis Complete</h2>
          <p className="text-sm text-steel">
            Report generated for {report.file_name} in {report.pipeline_duration_seconds}s
          </p>
        </div>
        <button 
          onClick={onExport} 
          disabled={isExporting}
          className="flex items-center gap-2 rounded bg-ink px-4 py-2 text-sm font-bold text-white transition hover:bg-slate-800 disabled:opacity-50" 
          type="button"
        >
          <Download size={16} />
          {isExporting ? "Exporting PDF..." : "Export PDF"}
        </button>
      </section>
      <ExecutiveKPI report={report} />
      <SummaryCards report={report} />
      <AIAnalystPanel report={report} />
      <Charts report={report} />
      <MLPerformance report={report} />
      <ThreatTable rows={report.ml.top_threats} />
    </div>
  );
}

function SummaryCards({ report }: { report: Report }) {
  let campaignSeverity = "UNKNOWN";
  const maxRisk = report.ml.top_threats.length > 0 ? report.ml.top_threats[0].danger_score : 0;
  if (maxRisk >= 90) campaignSeverity = "CRITICAL";
  else if (maxRisk >= 70) campaignSeverity = "HIGH";
  else if (maxRisk >= 40) campaignSeverity = "MEDIUM";
  else if (maxRisk > 0) campaignSeverity = "LOW";

  const aiSeverityColor = {
    "CRITICAL": "#dc2626",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "UNKNOWN": "#64748b",
  }[campaignSeverity] || "#64748b";

  const cards = [
    ["Total Records", report.summary.total_records, "CICIDS / uploaded CSV", "#475569"],
    ["Medium Risk", report.summary.suspicious_count, "Medium severity (40-69)", "#eab308"],
    ["High Risk", report.summary.likely_threat_count, "High severity (70-89)", "#f97316"],
    ["Campaign Severity", campaignSeverity, "Programmatic assessment", aiSeverityColor],
  ];
  return (
    <section className="grid gap-3 md:grid-cols-4">
      {cards.map(([label, value, sub, color]) => (
        <div key={label} className="relative overflow-hidden rounded-md border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold uppercase text-steel">{label}</p>
          <p className="mt-2 text-2xl font-black" style={{ color: color as string }}>
            {typeof value === "string" ? value : formatNumber(value as number)}
          </p>
          <p className="mt-1 text-xs text-steel">{sub as string}</p>
          <span className="absolute bottom-0 left-0 h-[3px]" style={{ width: "72%", backgroundColor: color as string }} />
        </div>
      ))}
    </section>
  );
}

function AIAnalystPanel({ report }: { report: Report }) {
  const ai = report.ai_analysis;
  if (!ai || report.ai_provider_used === "none") {
    return (
      <section className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-6 text-center text-sm font-medium text-slate-500 shadow-inner">
        🛡️ Enable AI explanation for plain-English analysis and recommended containment steps.
      </section>
    );
  }

  const maxRisk = report.ml.top_threats.length > 0 ? report.ml.top_threats[0].danger_score : 0;
  let sev = "UNKNOWN";
  if (maxRisk >= 90) sev = "CRITICAL";
  else if (maxRisk >= 70) sev = "HIGH";
  else if (maxRisk >= 40) sev = "MEDIUM";
  else if (maxRisk > 0) sev = "LOW";

  let bannerColor = "bg-red-50 text-red-700 border-red-200";
  let bannerText = "🔴 CAMPAIGN SEVERITY: CRITICAL — Act Now";
  if (sev === "HIGH") {
    bannerColor = "bg-orange-50 text-orange-700 border-orange-200";
    bannerText = "🟠 CAMPAIGN SEVERITY: HIGH — Active Threat Detected";
  } else if (sev === "MEDIUM") {
    bannerColor = "bg-yellow-50 text-yellow-800 border-yellow-200";
    bannerText = "🟡 CAMPAIGN SEVERITY: MEDIUM — Investigate Anomalous Traffic";
  } else if (sev === "LOW") {
    bannerColor = "bg-green-50 text-green-700 border-green-200";
    bannerText = "🟢 CAMPAIGN SEVERITY: LOW — Routine Monitoring";
  } else if (sev === "UNKNOWN") {
    bannerColor = "bg-slate-50 text-slate-600 border-slate-200";
    bannerText = "🔵 AI Analysis Complete";
  }

  const immediateActions: string[] = Array.isArray(ai.recommended_immediate_actions)
    ? (ai.recommended_immediate_actions as unknown as string[])
    : [];
  const longTermItems: string[] = Array.isArray(ai.long_term_mitigations)
    ? (ai.long_term_mitigations as unknown as string[])
    : [];

  const total = formatNumber(report.summary.total_records);
  const mostCommon = report.summary.most_common_attack || "suspicious";
  const uniqueSources = new Set(report.ml.top_threats.map(t => t.src_ip)).size;
  const targetPort = report.ml.top_threats.length > 0 ? report.ml.top_threats[0].dst_port : 80;
  
  let overrideSummary = `Analysis of ${total} network flows detected a coordinated ${mostCommon} campaign originating from ${uniqueSources} primary sources targeting web services on port ${targetPort}. `;
  if (report.summary.critical_count === 0) {
    overrideSummary += `No critical events were observed. Highest risk score was ${Math.round(maxRisk)}.`;
  } else {
    overrideSummary += `${report.summary.critical_count} critical events were observed. Highest risk score was ${Math.round(maxRisk)}.`;
  }

  return (
    <section className="rounded-lg border border-slate-200 bg-white overflow-hidden shadow-sm">
      <div className={`border-b px-5 py-3 text-sm font-bold flex items-center justify-between ${bannerColor}`}>
        <span>{bannerText}</span>
        <span className="text-xs font-semibold px-2 py-0.5 rounded border border-current opacity-85">
          Powered by {ai.provider === "gemini" ? "Gemini Flash" : ai.model || "Local AI"}
        </span>
      </div>
      <div className="p-5 space-y-4">
        {ai.error ? (
          <p className="text-sm text-red-600">{ai.error}</p>
        ) : (
          <>
            {/* Automated Summary */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Pipeline Summary</h4>
              <p className="text-sm text-slate-700 leading-relaxed font-semibold">
                {overrideSummary}
              </p>
            </div>

            {/* AI Report */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">AI Analyst Report</h4>
              <p className="text-sm text-slate-700 leading-relaxed">
                {ai.executive_summary || ai.what_is_happening || "No detailed report provided."}
              </p>
            </div>

            {/* Attack Types */}
            {ai.attack_types && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Attack Types Observed</h4>
                <p className="text-sm text-slate-700 leading-relaxed">{ai.attack_types}</p>
              </div>
            )}

            {/* Indicators of Compromise */}
            {ai.indicators_of_compromise && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Indicators of Compromise</h4>
                <p className="text-sm text-slate-700 leading-relaxed font-mono text-xs bg-slate-50 rounded p-2 border border-slate-100">
                  {ai.indicators_of_compromise}
                </p>
              </div>
            )}

            {/* MITRE ATT&CK */}
            {ai.mitre_attack_techniques && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">MITRE ATT&amp;CK Techniques</h4>
                <p className="text-sm text-slate-700 leading-relaxed">{ai.mitre_attack_techniques}</p>
              </div>
            )}

            <hr className="border-slate-100" />

            {/* Immediate Actions */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Immediate Actions Required</h4>
              {immediateActions.length > 0 ? (
                <ol className="list-decimal pl-5 space-y-1.5">
                  {immediateActions.map((action, i) => (
                    <li key={i} className="text-sm text-slate-800 font-semibold">{action}</li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm text-slate-500 italic">No immediate actions specified.</p>
              )}
            </div>

            {/* Long-term Mitigations */}
            {longTermItems.length > 0 && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Long-Term Mitigations</h4>
                <ol className="list-decimal pl-5 space-y-1.5">
                  {longTermItems.map((item, i) => (
                    <li key={i} className="text-sm text-slate-700">{item}</li>
                  ))}
                </ol>
              </div>
            )}

            <hr className="border-slate-100" />

            {/* Business Impact / CEO Summary */}
            <div className="bg-slate-50 rounded p-3.5 border border-slate-100">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">Business Impact</h4>
              <p className="text-sm text-slate-800 italic font-semibold">
                &ldquo;{ai.business_impact_assessment || ai.executive_summary || "No impact assessment provided."}&rdquo;
              </p>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

function Charts({ report }: { report: Report }) {
  const threatIps = useMemo(() => {
    const set = new Set<string>();
    report.ml.top_threats.forEach(t => {
      if (t.threat_category !== "safe" && t.src_ip) {
        set.add(t.src_ip);
      }
    });
    return set;
  }, [report]);

  const threatBreakdown = [
    { name: "Safe", value: report.summary.safe_count, color: CATEGORY_LABELS.safe.color },
    { name: "Medium Risk", value: report.summary.suspicious_count, color: CATEGORY_LABELS.suspicious.color },
    { name: "High Risk", value: report.summary.likely_threat_count, color: CATEGORY_LABELS.likely_threat.color },
    { name: "Critical", value: report.summary.critical_count, color: CATEGORY_LABELS.critical.color },
  ];

  return (
    <section className="grid gap-4 xl:grid-cols-2">
      <ChartBox title="Attack Spike Timeline">
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={report.eda.traffic_over_time}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
            <XAxis dataKey="bucket" hide />
            <YAxis />
            <Tooltip 
              contentStyle={{ backgroundColor: "#ffffff", borderRadius: "8px", border: "1px solid #e2e8f0" }}
              labelFormatter={(label) => `Time: ${new Date(label).toLocaleString()}`}
            />
            <Line name="Total Traffic" type="monotone" dataKey="count" stroke="#64748b" strokeWidth={2} dot={false} />
            <Line name="Flagged Threats" type="monotone" dataKey="flagged_count" stroke="#e24b4a" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </ChartBox>

      <ChartBox title="Threat Breakdown">
        <div className="grid grid-cols-[1.2fr_1fr] items-center gap-4">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={threatBreakdown} dataKey="value" nameKey="name" innerRadius={55} outerRadius={80} paddingAngle={2}>
                {threatBreakdown.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip formatter={(value) => formatNumber(value as number)} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-2.5 text-xs">
            {threatBreakdown.map((entry) => {
              const pct = report.summary.total_records ? ((entry.value || 0) / report.summary.total_records * 100).toFixed(2) : "0";
              return (
                <div key={entry.name} className="flex items-center justify-between border-b border-slate-50 pb-1.5 last:border-b-0">
                  <div className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: entry.color }} />
                    <span className="font-semibold text-slate-600">{entry.name}</span>
                  </div>
                  <span className="font-mono text-slate-900 font-bold">
                    {formatNumber(entry.value)} ({pct}%)
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </ChartBox>

      <ChartBox title="Top Source IPs">
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={report.eda.top_source_ips} layout="vertical" margin={{ left: 10, right: 10 }}>
            <XAxis type="number" stroke="#94a3b8" />
            <YAxis type="category" dataKey="ip" stroke="#94a3b8" width={90} className="font-mono text-[10px]" />
            <Tooltip contentStyle={{ borderRadius: "8px" }} />
            <Bar dataKey="count">
              {report.eda.top_source_ips.map((entry, index) => {
                const isThreat = threatIps.has(entry.ip);
                return <Cell key={`cell-${index}`} fill={isThreat ? "#dc2626" : "#64748b"} />;
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartBox>

      <ChartBox title="Top Target Ports">
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={report.eda.top_dest_ports} layout="vertical" margin={{ left: 10, right: 10 }}>
            <XAxis type="number" stroke="#94a3b8" />
            <YAxis type="category" dataKey="port" stroke="#94a3b8" width={60} className="font-mono text-[10px]" />
            <Tooltip contentStyle={{ borderRadius: "8px" }} />
            <Bar dataKey="count" fill="#0f766e" />
          </BarChart>
        </ResponsiveContainer>
      </ChartBox>
    </section>
  );
}

function ChartBox({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded border border-slate-200 bg-white p-4 shadow-sm">
      <h3 className="mb-3 text-sm font-bold uppercase text-steel">{title}</h3>
      {children}
    </div>
  );
}

function ThreatTable({ rows }: { rows: ThreatRow[] }) {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>("all");
  const [portFilter, setPortFilter] = useState<string>("all");
  const [srcIpFilter, setSrcIpFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [selectedThreat, setSelectedThreat] = useState<ThreatRow | null>(null);

  const uniqueAttackTypes = useMemo(() => {
    const set = new Set<string>();
    rows.forEach(r => { if (r.threat_type) set.add(r.threat_type); });
    return Array.from(set).sort();
  }, [rows]);

  const uniquePorts = useMemo(() => {
    const set = new Set<string>();
    rows.forEach(r => { if (r.dst_port) set.add(String(r.dst_port)); });
    return Array.from(set).sort((a, b) => Number(a) - Number(b));
  }, [rows]);

  const uniqueSrcIps = useMemo(() => {
    const set = new Set<string>();
    rows.forEach(r => { if (r.src_ip) set.add(r.src_ip); });
    return Array.from(set).sort();
  }, [rows]);

  const filtered = useMemo(() => {
    return rows
      .filter((row) => severityFilter === "all" || row.threat_category === severityFilter)
      .filter((row) => attackTypeFilter === "all" || row.threat_type === attackTypeFilter)
      .filter((row) => portFilter === "all" || String(row.dst_port) === portFilter)
      .filter((row) => srcIpFilter === "all" || row.src_ip === srcIpFilter)
      .filter((row) => {
        const q = query.toLowerCase().trim();
        if (!q) return true;
        const ipMatch = `${row.src_ip} ${row.dst_ip}`.toLowerCase().includes(q);
        const threatMatch = `${row.threat_type} ${row.mitre_id || ""} ${row.mitre_technique || ""}`.toLowerCase().includes(q);
        return ipMatch || threatMatch;
      })
      .sort((a, b) => b.danger_score - a.danger_score);
  }, [severityFilter, attackTypeFilter, portFilter, srcIpFilter, query, rows]);

  const Row = ({ index, style }: ListChildComponentProps) => {
    const row = filtered[index];
    const label = CATEGORY_LABELS[row.threat_category];
    return (
      <div 
        style={style} 
        className="grid grid-cols-[40px_1fr_1fr_60px_60px_1fr_1.2fr_90px_90px] items-center border-b border-slate-100 px-3 text-xs cursor-pointer hover:bg-slate-50 transition"
        onClick={() => setSelectedThreat(row)}
      >
        <span className="font-semibold text-slate-500">{row.rank}</span>
        <span className="truncate font-mono font-medium" title={row.src_ip}>
          {row.src_ip} <span className="text-slate-400 text-[10px]">({row.occurrences || 1})</span>
        </span>
        <span className="truncate font-mono font-medium" title={row.dst_ip}>{row.dst_ip}</span>
        <span className="font-mono">{row.dst_port}</span>
        <span className="font-semibold text-slate-600 uppercase">{row.protocol}</span>
        <span className="truncate font-semibold text-slate-700">{row.threat_type}</span>
        <span className="truncate text-slate-600" title={row.mitre_technique || ""}>
          {row.mitre_id ? (
            <a href={`https://attack.mitre.org/techniques/${row.mitre_id.split('.')[0]}`} target="_blank" rel="noreferrer" className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[10px] text-blue-600 hover:underline mr-1">{row.mitre_id}</a>
          ) : null}
          {row.mitre_technique || "N/A"}
        </span>
        <div className="flex flex-col pr-2 justify-center leading-tight">
          <div className="flex items-center gap-1">
            <span className="text-[10px] font-bold text-slate-700">{Math.round(row.danger_score)}</span>
            <span className="h-1 flex-1 overflow-hidden rounded bg-slate-100">
              <span className="block h-full" style={{ width: `${row.danger_score}%`, backgroundColor: label.color }} />
            </span>
          </div>
          <span className="text-[9px] text-slate-400">Avg: {row.avg_risk_score || row.danger_score}</span>
        </div>
        <span className={`w-fit rounded border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${label.bg}`}>{label.label}</span>
      </div>
    );
  };

  return (
    <>
      <section className="rounded border border-slate-200 bg-white p-4 shadow-sm">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h3 className="flex items-center gap-2 text-lg font-black">
            <FileText size={20} />
            Top Threat Sources
          </h3>
          <div className="flex flex-wrap gap-2">
          <label className="flex items-center gap-2 rounded border border-slate-200 px-2 py-1 text-xs">
            <Filter size={13} className="text-slate-400" />
            <select className="bg-transparent outline-none max-w-[120px]" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
              <option value="all">All Severity</option>
              <option value="critical">Critical (90-100)</option>
              <option value="likely_threat">High (70-89)</option>
              <option value="suspicious">Medium (40-69)</option>
              <option value="safe">Low (0-39)</option>
            </select>
          </label>
          {uniqueAttackTypes.length > 0 && (
            <label className="flex items-center gap-2 rounded border border-slate-200 px-2 py-1 text-xs">
              <Filter size={13} className="text-slate-400" />
              <select className="bg-transparent outline-none max-w-[120px]" value={attackTypeFilter} onChange={(event) => setAttackTypeFilter(event.target.value)}>
                <option value="all">All Attacks</option>
                {uniqueAttackTypes.map((type) => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </label>
          )}
          {uniquePorts.length > 0 && (
            <label className="flex items-center gap-2 rounded border border-slate-200 px-2 py-1 text-xs">
              <Filter size={13} className="text-slate-400" />
              <select className="bg-transparent outline-none max-w-[100px]" value={portFilter} onChange={(event) => setPortFilter(event.target.value)}>
                <option value="all">All Target Ports</option>
                {uniquePorts.map((port) => (
                  <option key={port} value={port}>Port {port}</option>
                ))}
              </select>
            </label>
          )}
          {uniqueSrcIps.length > 0 && uniqueSrcIps.length < 50 && (
            <label className="flex items-center gap-2 rounded border border-slate-200 px-2 py-1 text-xs">
              <Filter size={13} className="text-slate-400" />
              <select className="bg-transparent outline-none max-w-[140px]" value={srcIpFilter} onChange={(event) => setSrcIpFilter(event.target.value)}>
                <option value="all">All Source IPs</option>
                {uniqueSrcIps.map((ip) => (
                  <option key={ip} value={ip}>{ip}</option>
                ))}
              </select>
            </label>
          )}
          <label className="flex items-center gap-2 rounded border border-slate-200 px-2 py-1 text-xs">
            <Search size={13} className="text-slate-400" />
            <input className="w-32 outline-none" placeholder="Search IP/Threat" value={query} onChange={(event) => setQuery(event.target.value)} />
          </label>
        </div>
      </div>
      <div className="grid grid-cols-[40px_1fr_1fr_60px_60px_1fr_1.2fr_90px_90px] border-y border-slate-200 bg-slate-50 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-steel">
        <span>#</span>
        <span>Source IP (Occurrences)</span>
        <span>Dest IP</span>
        <span>Port</span>
        <span>Proto</span>
        <span>Threat Type</span>
        <span>MITRE ATT&CK</span>
        <span>Risk (Avg)</span>
        <span>Severity</span>
      </div>
      <FixedSizeList height={Math.min(360, Math.max(80, filtered.length * 48))} itemCount={filtered.length} itemSize={48} width="100%">
        {Row}
      </FixedSizeList>
    </section>

    {/* Detail Modal */}
    {selectedThreat && (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
        <div className="max-h-[90vh] w-full max-w-2xl overflow-auto rounded-lg bg-white shadow-2xl">
          <div className="border-b border-slate-200 bg-slate-50 px-6 py-4 flex items-center justify-between sticky top-0">
            <h2 className="text-lg font-bold">Threat Details: {selectedThreat.threat_type}</h2>
            <button onClick={() => setSelectedThreat(null)} className="text-slate-400 hover:text-slate-600 text-2xl leading-none">×</button>
          </div>
          
          <div className="p-6 space-y-4">
            {/* Basic Info */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase mb-1">Source IP</p>
                <p className="text-sm font-mono font-semibold text-slate-800">{selectedThreat.src_ip}</p>
              </div>
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase mb-1">Destination IP</p>
                <p className="text-sm font-mono font-semibold text-slate-800">{selectedThreat.dst_ip}</p>
              </div>
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase mb-1">Target Port</p>
                <p className="text-sm font-mono font-semibold text-slate-800">{selectedThreat.dst_port}</p>
              </div>
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase mb-1">Protocol</p>
                <p className="text-sm font-mono font-semibold text-slate-800">{selectedThreat.protocol}</p>
              </div>
            </div>

            <hr className="border-slate-100" />

            {/* Risk Scoring */}
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase mb-3">Risk Assessment</p>
              <div className="space-y-2">
                <div>
                  <div className="flex justify-between mb-1 text-xs">
                    <span className="font-semibold text-slate-700">Danger Score</span>
                    <span className="font-bold">{Math.round(selectedThreat.danger_score)}/100</span>
                  </div>
                  <div className="h-2 bg-slate-100 rounded overflow-hidden">
                    <div className="h-full" style={{ width: `${selectedThreat.danger_score}%`, backgroundColor: CATEGORY_LABELS[selectedThreat.threat_category].color }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between mb-1 text-xs">
                    <span className="font-semibold text-slate-700">Anomaly Score</span>
                    <span className="font-bold">{Math.round(selectedThreat.anomaly_score)}/100</span>
                  </div>
                  <div className="h-2 bg-slate-100 rounded overflow-hidden">
                    <div className="h-full w-1/2 bg-orange-500" />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between mb-1 text-xs" title="Confidence derived from Random Forest probability.">
                    <span className="font-semibold text-slate-700 underline decoration-dotted decoration-slate-400 cursor-help">Confidence Score</span>
                    <span className="font-bold">{(selectedThreat.rf_confidence * 100).toFixed(1)}%</span>
                  </div>
                  <div className="h-2 bg-slate-100 rounded overflow-hidden">
                    <div className="h-full" style={{ width: `${selectedThreat.rf_confidence * 100}%`, backgroundColor: "#0f766e" }} />
                  </div>
                </div>
              </div>
            </div>

            <hr className="border-slate-100" />

            {/* MITRE ATT&CK */}
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase mb-2">MITRE ATT&CK</p>
              <div className="bg-slate-50 rounded p-3 border border-slate-200">
                <p className="font-mono text-sm font-bold text-slate-800">{selectedThreat.mitre_id || "N/A"}</p>
                <p className="text-sm text-slate-600 mt-1">{selectedThreat.mitre_technique || "No technique mapped"}</p>
              </div>
            </div>

            <hr className="border-slate-100" />

            {/* Key Findings */}
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase mb-2">🔍 Key Indicators</p>
              <ul className="text-sm space-y-1 text-slate-700">
                <li>• <span className="font-semibold">Attack Type:</span> {selectedThreat.threat_type}</li>
                <li>• <span className="font-semibold">Anomaly Label:</span> {selectedThreat.anomaly_label}</li>
                <li>• <span className="font-semibold">Original Label:</span> {selectedThreat.original_label}</li>
                <li>• <span className="font-semibold">Severity:</span> {selectedThreat.severity}</li>
              </ul>
            </div>

            {selectedThreat.shap_features && selectedThreat.shap_features.length > 0 && (
              <>
                <hr className="border-slate-100" />
                <div>
                  <p className="text-xs font-bold text-slate-400 uppercase mb-2">Top Features Contributing (SHAP)</p>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {selectedThreat.shap_features.map((f, i) => (
                      <div key={i} className="flex justify-between items-center bg-slate-50 border border-slate-200 px-3 py-1.5 rounded text-sm">
                        <span className="font-mono text-xs text-slate-600 truncate mr-2">{f.name}</span>
                        <span className="font-bold text-red-600">+{Math.round(f.score * 100)}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}

            {/* Close Button */}
            <div className="pt-4">
              <button 
                onClick={() => setSelectedThreat(null)}
                className="w-full py-2 px-4 bg-slate-100 hover:bg-slate-200 rounded font-semibold text-slate-700 transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    )}
    </>
  );
}

function ExecutiveKPI({ report }: { report: Report }) {
  let highestRisk = 0;
  let mostTargetedServer = "N/A";
  let mostAggressiveIP = "N/A";
  
  if (report.ml.top_threats.length > 0) {
    highestRisk = report.ml.top_threats[0].danger_score;
    const occurrences = report.ml.top_threats[0].occurrences || 1;
    mostAggressiveIP = `${report.ml.top_threats[0].src_ip} (${occurrences} occurrences)`;
    
    // Find most targeted server
    const dstCounts: Record<string, number> = {};
    report.ml.top_threats.forEach(t => {
      if (t.threat_category !== "safe" && t.dst_ip) {
        dstCounts[t.dst_ip] = (dstCounts[t.dst_ip] || 0) + 1;
      }
    });
    const sortedDst = Object.entries(dstCounts).sort((a, b) => b[1] - a[1]);
    if (sortedDst.length > 0) mostTargetedServer = sortedDst[0][0];
  }

  const kpis = [
    { title: "Highest Risk Score", value: highestRisk ? Math.round(highestRisk) : "N/A", icon: <Zap size={18} className="text-red-500" /> },
    { title: "Most Targeted Server", value: mostTargetedServer, icon: <Server size={18} className="text-blue-500" /> },
    { title: "Most Aggressive Source", value: mostAggressiveIP, icon: <Target size={18} className="text-orange-500" /> },
    { title: "Most Common Attack", value: report.summary.most_common_attack || "N/A", icon: <ShieldAlert size={18} className="text-yellow-500" /> },
  ];

  return (
    <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {kpis.map((kpi) => (
        <div key={kpi.title} className="flex items-center gap-3 rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-50 border border-slate-100">
            {kpi.icon}
          </div>
          <div className="overflow-hidden">
            <p className="text-xs font-bold uppercase text-slate-400">{kpi.title}</p>
            <p className="truncate text-lg font-black text-slate-800">{kpi.value}</p>
          </div>
        </div>
      ))}
    </section>
  );
}

function MLPerformance({ report }: { report: Report }) {
  if (!report.ml.supervised_available) return null;
  
  const acc = report.ml.model_accuracy;
  const prec = report.ml.model_precision || acc;
  const rec = report.ml.model_recall || acc;
  const f1 = report.ml.model_f1 || acc;

  const formatPct = (val: number | null | undefined) => val ? `${(val * 100).toFixed(2)}%` : "N/A";

  return (
    <section className="rounded border border-slate-200 bg-white shadow-sm overflow-hidden">
      <div className="border-b border-slate-200 bg-slate-50 px-4 py-3 font-bold text-sm flex justify-between items-center">
        <h3 className="flex items-center gap-2 text-slate-700">
          <Brain size={18} className="text-indigo-500" />
          Model Performance (Random Forest)
        </h3>
        <span className="rounded bg-indigo-100 px-2 py-0.5 text-xs font-bold text-indigo-700 uppercase">Supervised Validation Active</span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-y md:divide-y-0 divide-slate-100">
        <div className="p-4 text-center">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Accuracy</p>
          <p className="mt-1 text-xl font-black text-slate-800">{formatPct(acc)}</p>
        </div>
        <div className="p-4 text-center">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Precision</p>
          <p className="mt-1 text-xl font-black text-slate-800">{formatPct(prec)}</p>
        </div>
        <div className="p-4 text-center">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Recall</p>
          <p className="mt-1 text-xl font-black text-slate-800">{formatPct(rec)}</p>
        </div>
        <div className="p-4 text-center">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">F1 Score</p>
          <p className="mt-1 text-xl font-black text-slate-800">{formatPct(f1)}</p>
        </div>
      </div>
    </section>
  );
}

function LiveAssetScan({ provider, geminiKey, ollamaModel }: { provider: AiProvider; geminiKey: string; ollamaModel: string }) {
  const [target, setTarget] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [useAi, setUseAi] = useState(provider !== "none");
  const [copied, setCopied] = useState(false);

  const handleScan = async () => {
    if (!target) return;
    setIsScanning(true);
    setError(null);
    setScanResult(null);
    try {
      let cleanTarget = target.replace("https://", "").replace("http://", "").split("/")[0];
      let url = `${API_BASE}/api/scan?target=${encodeURIComponent(cleanTarget)}`;
      if (useAi) {
        url += `&ai_provider=${provider}`;
        if (provider === "gemini") {
          url += `&gemini_api_key=${encodeURIComponent(geminiKey)}`;
        } else if (provider === "ollama") {
          url += `&ollama_model=${encodeURIComponent(ollamaModel)}`;
        }
      }
      
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error("Scan failed");
      }
      const data = await response.json();
      if (data.error) {
        setError(data.error);
      } else {
        setScanResult(data);
      }
    } catch (e: any) {
      setError(e.message || "An error occurred during the scan");
    } finally {
      setIsScanning(false);
    }
  };

  const copyToClipboard = () => {
    if (scanResult && scanResult.vulnerability_report) {
      navigator.clipboard.writeText(scanResult.vulnerability_report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <section className="mx-auto max-w-4xl px-4 py-8 space-y-6">
      {/* Scanner Input Panel */}
      <div className="bg-white p-6 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#e24b4a] text-white">
            <ShieldAlert size={22} />
          </div>
          <div>
            <h2 className="text-xl font-black text-slate-800">Asset Exposure Intelligence</h2>
            <p className="text-xs text-steel mt-0.5">Built with Python socket scanning and dynamic AI/static reporting.</p>
          </div>
        </div>

        <p className="text-sm text-slate-600 mt-4 leading-relaxed">
          Scan a target for common open ports, identify basic security risks, and generate a vulnerability assessment report.
        </p>

        <div className="mt-5 space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <input 
              type="text" 
              placeholder="Example: google.com or 192.168.1.1" 
              className="flex-1 rounded border border-slate-300 px-3 py-2 text-sm font-mono placeholder:font-sans focus:border-[#e24b4a] focus:ring-1 focus:ring-[#e24b4a] focus:outline-none"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleScan()}
            />
            <button 
              className="rounded bg-ink px-5 py-2.5 text-sm font-bold text-white transition hover:bg-slate-800 disabled:opacity-50 flex items-center justify-center gap-2"
              onClick={handleScan}
              disabled={isScanning || !target}
            >
              {isScanning ? <Activity size={16} className="animate-spin" /> : <Search size={16} />}
              {isScanning ? "Scanning..." : "Start Scan"}
            </button>
          </div>

          <div className="flex flex-col gap-2">
            <label className="inline-flex items-center gap-2 cursor-pointer text-sm font-medium text-slate-700">
              <input
                type="checkbox"
                checked={useAi}
                onChange={e => setUseAi(e.target.checked)}
                className="rounded border-slate-300 text-[#e24b4a] focus:ring-[#e24b4a]"
              />
              <span>Enable AI Threat Report</span>
            </label>
            {useAi && provider === "none" && (
              <p className="text-xs text-orange-600 flex items-center gap-1">
                ⚠️ Select Gemini or Ollama on the Threat Analysis tab to use AI. Otherwise, a detailed static report will be generated.
              </p>
            )}
            {useAi && provider !== "none" && (
              <p className="text-xs text-green-700 flex items-center gap-1">
                ✨ Report will be generated using {provider === "gemini" ? "Google Gemini" : `Ollama model '${ollamaModel}'`}.
              </p>
            )}
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 rounded border border-red-200 bg-red-50 text-sm font-semibold text-red-600">
            {error}
          </div>
        )}
      </div>

      {isScanning && (
        <div className="bg-white p-8 rounded-lg border border-slate-200 shadow-sm text-center space-y-4">
          <Activity className="mx-auto animate-spin text-[#e24b4a]" size={36} />
          <div>
            <p className="text-sm font-bold text-slate-800">Scan in progress...</p>
            <p className="text-xs text-steel mt-1">Establishing TCP connections on common ports of target host...</p>
          </div>
        </div>
      )}

      {scanResult && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
          
          {/* 🔎 Scan Status */}
          <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
            <h3 className="text-base font-bold text-slate-800 flex items-center gap-2">
              <span>🔎</span> Scan Status
            </h3>
            <div className="mt-3 p-3.5 rounded border border-green-200 bg-green-50 text-sm text-green-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-green-500 animate-pulse" />
                <span className="font-semibold">Scan Completed Successfully</span>
              </div>
              <span className="font-mono text-xs bg-green-100 px-2 py-0.5 rounded text-green-700 font-bold">
                Resolved: {scanResult.ip_address}
              </span>
            </div>
            {scanResult.executive_summary && (
              <p className="mt-3 text-xs text-slate-500 leading-relaxed italic border-t border-slate-100 pt-3">
                {scanResult.executive_summary}
              </p>
            )}
          </div>

          {/* 📋 Open Ports */}
          <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
            <h3 className="text-base font-bold text-slate-800 flex items-center gap-2 mb-3">
              <span>📋</span> Open Ports
            </h3>
            {scanResult.open_ports.length > 0 ? (
              <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3">
                {scanResult.open_ports.map((portInfo, idx) => (
                  <div key={idx} className="flex items-center gap-2 p-2.5 rounded border border-green-200 bg-green-50/35 text-sm">
                    <span className="text-green-600">✅</span>
                    <span className="font-mono font-bold text-slate-700">Port {portInfo.port}</span>
                    <span className="text-xs bg-slate-200/80 px-1.5 py-0.5 rounded text-slate-600 font-semibold uppercase">
                      {portInfo.service}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-3.5 rounded border border-slate-200 bg-slate-50 text-sm text-slate-600 italic">
                No common open ports detected.
              </div>
            )}
          </div>

          {/* 🔍 Security Findings */}
          <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
            <h3 className="text-base font-bold text-slate-800 flex items-center gap-2 mb-3">
              <span>🔍</span> Security Findings
            </h3>
            {scanResult.findings.length > 0 ? (
              <div className="space-y-2.5">
                {scanResult.findings.map((finding, idx) => (
                  <div key={idx} className="flex gap-2.5 text-sm text-orange-800 bg-orange-50 border border-orange-200 p-3 rounded">
                    <span className="text-orange-500 shrink-0 text-base">⚠️</span>
                    <span className="font-medium">{finding}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-3.5 rounded border border-green-200 bg-green-50 text-sm text-green-700 flex items-center gap-2 font-medium">
                <span>✔</span> No obvious security issues detected.
              </div>
            )}
          </div>

          {/* 📊 Risk Assessment */}
          <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
            <h3 className="text-base font-bold text-slate-800 flex items-center gap-2 mb-3">
              <span>📊</span> Risk Assessment
            </h3>
            {(() => {
              const r = scanResult.severity;
              let bg = "bg-green-50 border-green-200 text-green-800";
              let badge = "bg-green-500 text-white";
              if (r === "CRITICAL" || r === "HIGH") {
                bg = "bg-red-50 border-red-200 text-red-800";
                badge = "bg-red-600 text-white";
              } else if (r === "MEDIUM") {
                bg = "bg-yellow-50 border-yellow-200 text-yellow-800";
                badge = "bg-yellow-500 text-white";
              }
              return (
                <div className={`p-4 rounded border ${bg} flex items-center justify-between`}>
                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded ${badge}`}>
                      {r} RISK
                    </span>
                    <span className="text-sm font-semibold">
                      Assessment calculated based on exposed services.
                    </span>
                  </div>
                  <span className="font-black text-xl">Score: {scanResult.risk_score}/100</span>
                </div>
              );
            })()}
          </div>

          {/* 📄 Vulnerability Report */}
          {scanResult.vulnerability_report && (
            <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center mb-3">
                <h3 className="text-base font-bold text-slate-800 flex items-center gap-2">
                  <span>📄</span> Vulnerability Report
                </h3>
                <button
                  onClick={copyToClipboard}
                  className="text-xs font-bold px-2.5 py-1.5 rounded border border-slate-200 hover:bg-slate-50 transition flex items-center gap-1.5 text-slate-600"
                >
                  {copied ? (
                    <>
                      <span>✔</span> Copied!
                    </>
                  ) : (
                    <>
                      <span>📋</span> Copy Report
                    </>
                  )}
                </button>
              </div>
              <textarea
                readOnly
                className="w-full h-80 p-4 rounded border border-slate-200 bg-slate-50 font-mono text-xs leading-relaxed text-slate-800 focus:outline-none resize-y"
                value={scanResult.vulnerability_report}
              />
            </div>
          )}

        </div>
      )}
    </section>
  );
}
