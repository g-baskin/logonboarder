// LogOnboard-AI Type Definitions

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type OutputFormat = 'zip' | 'txt';
export type SIEM = 'splunk' | 'elastic' | 'sentinel' | 'qradar' | 'cribl';

export interface AnalyzeOptions {
  runSensitiveScan: boolean;
  includeDomainsInConfigs: boolean;
  outputFormat: OutputFormat;
}

export interface AnalyzeRequest {
  paths: string[];
  siem: SIEM;
  options: AnalyzeOptions;
}

export interface SourcetypeMapping {
  sourcetype: string;
  index: string;
  category: string;
}

export interface PropsTemplate {
  SHOULD_LINEMERGE: string;
  LINE_BREAKER: string;
  TIME_FORMAT: string;
  TIME_PREFIX?: string;
  MAX_TIMESTAMP_LOOKAHEAD: string;
  KV_MODE: string;
  TRUNCATE: string;
  category: string;
}

export interface SensitivePattern {
  regex: string;
  description: string;
  risk_level: RiskLevel;
  mask_format: string;
}

export interface SensitiveFinding {
  pattern: string;
  description: string;
  riskLevel: RiskLevel;
  count: number;
  locations: string[];
  maskFormat: string;
}

export interface PathAnalysisResult {
  path: string;
  filename: string;
  directory: string;
  extension: string;
  sourcetype: string;
  index: string;
  category: string;
  confidence: 'high' | 'medium' | 'low';
  matchType: 'filename' | 'directory' | 'extension' | 'vendor' | 'fallback';
  vendor?: string;
}

export interface SplunkInputsStanza {
  path: string;
  sourcetype: string;
  index: string;
  disabled: number;
}

export interface SplunkPropsStanza {
  sourcetype: string;
  settings: Record<string, string>;
}

export interface SplunkTransformsStanza {
  name: string;
  regex: string;
  format: string;
  destKey: string;
}

// SIEM-specific config types
export interface SplunkConfig {
  inputsConf: string;
  propsConf: string;
  transformsConf: string;
}

export interface ElasticConfig {
  filebeatYml: string;
  ingestPipeline: string;
  indexTemplate: string;
}

export interface SentinelConfig {
  dataCollectionRule: string;
  analyticsRules: string;
  workbook: string;
}

export interface QRadarConfig {
  logSourceExtension: string;
  dsmConfig: string;
}

export interface CriblConfig {
  routes: string;
  pipelines: string;
  packs: string;
}

export interface GeneratedConfig {
  inputsConf: string;
  propsConf: string;
  transformsConf: string;
  readme: string;
  metadata: ConfigMetadata;
  // Multi-SIEM support
  siem?: SIEM;
  elastic?: ElasticConfig;
  sentinel?: SentinelConfig;
  qradar?: QRadarConfig;
  cribl?: CriblConfig;
}

export interface ConfigMetadata {
  generatedAt: string;
  version: string;
  pathCount: number;
  sourcetypes: string[];
  indexes: string[];
  sensitiveFindings: SensitiveFinding[];
  warnings: string[];
}

export interface AnalyzeResponse {
  success: boolean;
  pathAnalysis: PathAnalysisResult[];
  sensitiveFindings: SensitiveFinding[];
  generatedConfig: GeneratedConfig;
  downloadUrl?: string;
}
