export type AiProvider = "gemini" | "ollama" | "none";

export type ThreatCategory = "critical" | "likely_threat" | "suspicious" | "safe";

export interface ProgressEvent {
  stage: string;
  percent: number;
  message: string;
}

export interface ThreatRow {
  rank: number;
  src_ip: string;
  dst_ip: string;
  dst_port: number | string;
  protocol: string;
  danger_score: number;
  severity: string;
  threat_category: ThreatCategory;
  anomaly_score: number;
  rf_label: string | number;
  rf_confidence: number;
  original_label: string;
  threat_type: string;
  mitre_id: string | null;
  mitre_technique: string | null;
  anomaly_label?: string;
  timestamp?: string;
  src_ip_intel?: {
    is_malicious: boolean;
    reports: number;
    last_reported: string | null;
    source: string;
  };
  dst_ip_intel?: {
    is_malicious: boolean;
    reports: number;
    last_reported: string | null;
    source: string;
  };
  shap_features?: Array<{ name: string; score: number }>;
  threat_factors?: string;
  occurrences?: number;
  avg_risk_score?: number;
}

export interface Report {
  job_id: string;
  status: "complete" | "processing" | "error";
  file_name: string;
  processed_at: string;
  pipeline_duration_seconds: number;
  ai_provider_used: AiProvider;
  ollama_model_used: string | null;
  summary: {
    total_records: number;
    safe_count: number;
    suspicious_count: number;
    likely_threat_count: number;
    critical_count: number;
    threat_percentage: number;
    most_common_attack: string | null;
  };
  eda: {
    time_range: { start: string; end: string } | null;
    label_distribution: Record<string, number> | null;
    top_source_ips: Array<{ ip: string; count: number }>;
    top_dest_ports: Array<{ port: number | string; count: number }>;
    protocol_split: Record<string, number>;
    traffic_over_time: Array<{ bucket: string; count: number; flagged_count: number }>;
    packet_stats: Record<string, number> | null;
    flagged_ips: string[];
  };
  ml: {
    supervised_available: boolean;
    model_accuracy: number | null;
    model_precision?: number | null;
    model_recall?: number | null;
    model_f1?: number | null;
    classification_report: Record<string, unknown> | null;
    top_threats: ThreatRow[];
  };
  ai_analysis: null | {
    provider: AiProvider;
    model: string | null;
    records_analyzed: number;
    // Raw section fields from AI response
    executive_summary?: string;
    attack_types?: string;
    severity_assessment?: string;
    indicators_of_compromise?: string;
    mitre_attack_techniques?: string;
    recommended_immediate_actions?: string[];
    long_term_mitigations?: string[];
    business_impact_assessment?: string;
    // Frontend-friendly aliases added by backend
    what_is_happening?: string;
    actions?: string[];
    // Severity info
    severity?: string;
    severity_emoji?: string;
    // Meta
    raw_response?: string;
    error?: string;
  };
  error?: string;
}
