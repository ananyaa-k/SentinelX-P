export interface ScanResult {
  scan_id: string;
  filename: string;
  threat_level: 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE';
  confidence_score: number;
  detection_path: string;
  yara_result: { matched: boolean; matched_rules: string[] };
  llm_analysis: { verdict: string; reasoning: string; behavioral_flags: string[]; suspicious_strings?: string[] };
  generated_yara_rule: string | null;
  recommendation: string;
  processing_time_ms: number;
  ts: string;
  features_extracted?: Record<string, number>;
}

export interface BenchmarkMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  fnr: number;
  auc: number;
}

export interface BenchmarkResults {
  yara_only: BenchmarkMetrics;
  basic_ml: BenchmarkMetrics;
  sentinelx: BenchmarkMetrics;
  sample_count: number;
}

export interface DatasetInfo {
  total_samples: number;
  malware_count: number;
  benign_count: number;
  malware_families: string[];
  features: string[];
  family_distribution: Record<string, number>;
}

export interface DatasetSample {
  sha256: string;
  family: string;
  label: number;
  entropy: number;
  packed: boolean;
  yara_hit: boolean;
  threat_score: number;
}

export interface ModelInfo {
  architecture: {
    name: string;
    version: string;
    stages: { name: string; type: string; weight?: number; description: string }[];
  };
  fusion_weights: { gbm: number; llm: number };
  gbm_params: Record<string, number>;
  basic_ml_params: Record<string, string | number>;
  training_info: Record<string, string | number>;
}

export interface FeatureImportance {
  feature: string;
  importance: number;
  rank: number;
  description: string;
}
