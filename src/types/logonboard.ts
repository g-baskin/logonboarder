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

// Field extraction with sample values
export interface FieldExtraction {
  name: string;
  sampleValue: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array' | 'null';
  nested?: boolean;
  path?: string; // For nested JSON fields like "user.name"
}

// Platform/OS types for log files
export type LogPlatform =
  | 'windows'
  | 'linux'
  | 'unix'
  | 'macos'
  | 'aws'
  | 'azure'
  | 'gcp'
  | 'docker'
  | 'kubernetes'
  | 'cloud'
  | 'unknown';

// Log format types
export type LogFormat =
  | 'json'
  | 'xml'
  | 'csv'
  | 'cef' // Common Event Format
  | 'leef' // Log Event Extended Format
  | 'windows-evtx' // Windows Event Log
  | 'syslog'
  | 'apache'
  | 'nginx'
  | 'iis'
  | 'kv' // Key-value pairs
  | 'custom'
  | 'unknown';

// Input method for Splunk
export type SplunkInputMethod =
  | 'monitor' // Standard file monitoring
  | 'hec' // HTTP Event Collector (for JSON/structured)
  | 'scripted' // Scripted input
  | 'wmi' // Windows Management Instrumentation
  | 'powershell' // PowerShell scripts
  | 's3' // AWS S3
  | 'kinesis' // AWS Kinesis
  | 'cloudwatch' // AWS CloudWatch
  | 'azure-blob' // Azure Blob Storage
  | 'gcp-pubsub'; // GCP Pub/Sub

// Log sample analysis result - used to enhance props.conf generation
export interface LogSampleAnalysis {
  timeFormat: string | null;
  timePrefix: string | null;
  lineBreaker: string;
  kvMode: 'auto' | 'json' | 'none';
  maxTimestampLookahead: number;
  detectedFields: string[];
  extractedFields: FieldExtraction[]; // New: fields with sample values
  confidence: 'high' | 'medium' | 'low';
  sampleType: 'json' | 'kv' | 'syslog' | 'apache' | 'csv' | 'unknown';
  rawPattern: string | null;
  suggestedPaths: string[];
  detectedVendor: string | null;
  suggestedSourcetype: string | null;
  // New platform/format detection
  detectedPlatform: LogPlatform;
  detectedFormat: LogFormat;
  splunkInputMethod: SplunkInputMethod;
  inputMethodNotes?: string; // Special notes for non-standard input methods
}
