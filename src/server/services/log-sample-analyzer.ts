// Log Sample Analyzer - Detects timestamp formats, line breakers, and field patterns
// This eliminates guesswork by analyzing actual log samples

export interface LogSampleAnalysis {
  timeFormat: string | null;
  timePrefix: string | null;
  lineBreaker: string;
  kvMode: 'auto' | 'json' | 'none';
  maxTimestampLookahead: number;
  detectedFields: string[];
  confidence: 'high' | 'medium' | 'low';
  sampleType: 'json' | 'kv' | 'syslog' | 'apache' | 'csv' | 'unknown';
  rawPattern: string | null;
  suggestedPaths: string[]; // Suggested log paths based on detected log type
  detectedVendor: string | null; // e.g., "Palo Alto Networks", "Apache", "Cisco"
  suggestedSourcetype: string | null; // e.g., "pan:traffic", "apache:access", "linux_secure"
}

// Common timestamp patterns with their Splunk TIME_FORMAT equivalents
const TIMESTAMP_PATTERNS: { regex: RegExp; format: string; prefix?: string; lookahead: number }[] =
  [
    // ISO 8601 formats
    {
      regex: /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/,
      format: '%Y-%m-%dT%H:%M:%S.%3NZ',
      lookahead: 24,
    },
    {
      regex: /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z/,
      format: '%Y-%m-%dT%H:%M:%S.%6NZ',
      lookahead: 27,
    },
    {
      regex: /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}/,
      format: '%Y-%m-%dT%H:%M:%S%z',
      lookahead: 25,
    },
    {
      regex: /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,
      format: '%Y-%m-%dT%H:%M:%S',
      lookahead: 19,
    },
    {
      regex: /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}/,
      format: '%Y-%m-%d %H:%M:%S,%3N',
      lookahead: 23,
    },
    {
      regex: /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}/,
      format: '%Y-%m-%d %H:%M:%S.%3N',
      lookahead: 23,
    },
    {
      regex: /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/,
      format: '%Y-%m-%d %H:%M:%S',
      lookahead: 19,
    },

    // Syslog formats
    {
      regex: /[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/,
      format: '%b %d %H:%M:%S',
      lookahead: 15,
    },
    {
      regex: /[A-Z][a-z]{2}\s+\d{1,2},\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M/,
      format: '%b %d, %Y %I:%M:%S %p',
      lookahead: 25,
    },

    // Apache/NCSA Common Log Format
    {
      regex: /\[\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]/,
      format: '[%d/%b/%Y:%H:%M:%S %z]',
      prefix: '\\[',
      lookahead: 28,
    },

    // Windows Event Log
    {
      regex: /\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M/,
      format: '%m/%d/%Y %I:%M:%S %p',
      lookahead: 22,
    },

    // Unix epoch (seconds)
    {
      regex: /\b1[0-9]{9}\b/,
      format: '%s',
      lookahead: 10,
    },

    // Unix epoch (milliseconds)
    {
      regex: /\b1[0-9]{12}\b/,
      format: '%s%3N',
      lookahead: 13,
    },

    // DD/MM/YYYY formats
    {
      regex: /\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2}/,
      format: '%d/%m/%Y %H:%M:%S',
      lookahead: 19,
    },

    // MM-DD-YYYY formats
    {
      regex: /\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2}/,
      format: '%m-%d-%Y %H:%M:%S',
      lookahead: 19,
    },

    // YYYY/MM/DD HH:MM:SS (Palo Alto, Cisco, many firewall logs)
    {
      regex: /\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}/,
      format: '%Y/%m/%d %H:%M:%S',
      lookahead: 19,
    },

    // DD-Mon-YYYY HH:MM:SS (Oracle, some enterprise apps)
    {
      regex: /\d{2}-[A-Z][a-z]{2}-\d{4}\s+\d{2}:\d{2}:\d{2}/,
      format: '%d-%b-%Y %H:%M:%S',
      lookahead: 20,
    },

    // Mon DD YYYY HH:MM:SS (some Windows formats)
    {
      regex: /[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}/,
      format: '%b %d %Y %H:%M:%S',
      lookahead: 20,
    },
  ];

export function analyzeLogSample(sample: string): LogSampleAnalysis {
  const lines = sample.trim().split('\n');
  const firstLine = lines[0] || '';

  // Detect sample type
  const sampleType = detectSampleType(firstLine);

  // Detect timestamp
  const timestampInfo = detectTimestamp(firstLine);

  // Detect KV mode
  const kvMode = detectKVMode(firstLine, sampleType);

  // Detect fields
  const detectedFields = detectFields(firstLine, sampleType);

  // Detect line breaker
  const lineBreaker = detectLineBreaker(lines);

  // Detect vendor and suggest paths
  const vendorInfo = detectVendorAndPaths(firstLine, detectedFields);

  // Calculate confidence
  const confidence = calculateConfidence(timestampInfo, sampleType, detectedFields);

  return {
    timeFormat: timestampInfo?.format || null,
    timePrefix: timestampInfo?.prefix || null,
    lineBreaker,
    kvMode,
    maxTimestampLookahead: timestampInfo?.lookahead || 150,
    detectedFields,
    confidence,
    sampleType,
    rawPattern: timestampInfo?.rawMatch || null,
    suggestedPaths: vendorInfo.paths,
    detectedVendor: vendorInfo.vendor,
    suggestedSourcetype: vendorInfo.sourcetype,
  };
}

function detectSampleType(line: string): 'json' | 'kv' | 'syslog' | 'apache' | 'csv' | 'unknown' {
  const trimmed = line.trim();

  // JSON detection
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      JSON.parse(trimmed);
      return 'json';
    } catch {
      // Not valid JSON
    }
  }

  // Apache Combined/Common Log Format
  if (/^\S+\s+\S+\s+\S+\s+\[.*\]\s+"[A-Z]+\s+/.test(trimmed)) {
    return 'apache';
  }

  // Syslog format
  if (/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+/.test(trimmed)) {
    return 'syslog';
  }

  // CSV detection (comma-separated with consistent field count)
  const commaCount = (trimmed.match(/,/g) || []).length;
  if (commaCount >= 3 && !trimmed.includes('=')) {
    return 'csv';
  }

  // Key=Value detection
  if (/\w+=["']?[^"'\s]+["']?/.test(trimmed)) {
    return 'kv';
  }

  return 'unknown';
}

function detectTimestamp(
  line: string
): { format: string; prefix: string | null; lookahead: number; rawMatch: string } | null {
  for (const pattern of TIMESTAMP_PATTERNS) {
    const match = line.match(pattern.regex);
    if (match) {
      return {
        format: pattern.format,
        prefix: pattern.prefix || null,
        lookahead: pattern.lookahead,
        rawMatch: match[0],
      };
    }
  }

  return null;
}

function detectKVMode(line: string, sampleType: string): 'auto' | 'json' | 'none' {
  if (sampleType === 'json') {
    return 'json';
  }

  // Count key=value pairs
  const kvMatches = line.match(/\w+=["']?[^"'\s,]+["']?/g) || [];
  if (kvMatches.length >= 3) {
    return 'auto';
  }

  return 'none';
}

function detectFields(line: string, sampleType: string): string[] {
  const fields: string[] = [];

  if (sampleType === 'json') {
    try {
      const parsed = JSON.parse(line.trim());
      return Object.keys(parsed).slice(0, 20); // Limit to first 20 fields
    } catch {
      return [];
    }
  }

  if (sampleType === 'kv') {
    const matches = line.match(/(\w+)=["']?[^"'\s,]+["']?/g) || [];
    for (const match of matches.slice(0, 20)) {
      const [key] = match.split('=');
      if (key) fields.push(key);
    }
    return fields;
  }

  if (sampleType === 'apache') {
    return [
      'clientip',
      'ident',
      'user',
      'timestamp',
      'method',
      'uri',
      'status',
      'bytes',
      'referer',
      'useragent',
    ];
  }

  if (sampleType === 'syslog') {
    return ['timestamp', 'host', 'process', 'pid', 'message'];
  }

  return fields;
}

function detectLineBreaker(lines: string[]): string {
  if (lines.length <= 1) {
    return '([\\r\\n]+)';
  }

  // Check for multi-line events (e.g., stack traces)
  const hasIndentedLines = lines.some(
    (line, i) => i > 0 && (line.startsWith(' ') || line.startsWith('\t'))
  );

  if (hasIndentedLines) {
    // Multi-line events - break on lines that start with timestamp or non-whitespace
    return '([\\r\\n]+)(?=\\d|[A-Z][a-z]{2}\\s)';
  }

  return '([\\r\\n]+)';
}

// Vendor detection patterns - extensible and pattern-based
// Based on industry best practices and official SIEM add-on documentation (2025)
interface VendorPattern {
  name: string;
  indicators: string[]; // Keywords/patterns to look for
  logTypeDetection?: (line: string) => string | null; // Optional log type detector
  sourcetypePrefix: string; // e.g., "pan", "cisco", "aws"
  useUnderscoreFormat?: boolean; // Some vendors use underscores instead of colons (legacy)
}

const VENDOR_PATTERNS: VendorPattern[] = [
  // Palo Alto Networks - Best Practice: pan:<logtype>
  // Reference: https://pan.dev/splunk/docs/log-correlation/
  {
    name: 'Palo Alto Networks',
    indicators: [',traffic,', ',threat,', ',system,', ',config,', ',userid,', ',globalprotect,'],
    logTypeDetection: (line: string) => {
      const lower = line.toLowerCase();
      // Detect specific log type from CSV field
      if (lower.includes(',traffic,')) return 'traffic';
      if (lower.includes(',threat,')) return 'threat';
      if (lower.includes(',system,')) return 'system';
      if (lower.includes(',config,')) return 'config';
      if (lower.includes(',userid,')) return 'userid';
      if (lower.includes(',globalprotect,')) return 'globalprotect';
      // High comma count + PAN timestamp pattern = traffic log (most common)
      const commaCount = (line.match(/,/g) || []).length;
      if (commaCount > 40 && /^\d+,\d{4}\/\d{2}\/\d{2}/.test(line)) return 'traffic';
      return null;
    },
    sourcetypePrefix: 'pan',
  },

  // Cisco ASA/Firepower - Best Practice: cisco:asa, cisco:firepower
  // Reference: https://docs.splunk.com/Documentation/AddOns/released/CiscoASA/
  {
    name: 'Cisco',
    indicators: ['cisco', '%asa-', '%fpr-', '%sec-', 'asa:', 'firepower', '%ftd-'],
    logTypeDetection: (line: string) => {
      const lower = line.toLowerCase();
      if (lower.includes('%asa-') || lower.includes('asa:')) return 'asa';
      if (lower.includes('%fpr-') || lower.includes('firepower') || lower.includes('%ftd-'))
        return 'firepower';
      if (lower.includes('%sec-')) return 'security';
      return 'asa'; // Default to ASA
    },
    sourcetypePrefix: 'cisco',
  },

  // Fortinet FortiGate - Best Practice: fgt_traffic, fgt_utm, fgt_event (underscore format per official add-on)
  // Reference: https://splunkbase.splunk.com/app/2846
  {
    name: 'Fortinet',
    indicators: [
      'fortigate',
      'fortinet',
      'devname=',
      'logid=',
      'type="traffic"',
      'type="utm"',
      'type="event"',
    ],
    logTypeDetection: (line: string) => {
      const lower = line.toLowerCase();
      if (lower.includes('type="traffic"') || lower.includes("type='traffic'")) return 'traffic';
      if (lower.includes('type="utm"') || lower.includes("type='utm'")) return 'utm';
      if (lower.includes('type="event"') || lower.includes("type='event'")) return 'event';
      return 'traffic'; // Default to traffic (most common)
    },
    sourcetypePrefix: 'fgt',
    useUnderscoreFormat: true, // Official add-on uses underscores
  },

  // Check Point - Best Practice: cp_log
  // Reference: https://sc1.checkpoint.com/documents/App_for_Splunk/
  {
    name: 'Check Point',
    indicators: ['checkpoint', 'fw_log', 'product="vpn-1"', 'smartdefense', 'product="firewall-1"'],
    logTypeDetection: () => 'log',
    sourcetypePrefix: 'cp',
    useUnderscoreFormat: true, // Check Point uses underscore format
  },

  // AWS - Best Practice: aws:cloudtrail, aws:cloudwatch:vpcflow
  // Reference: https://docs.splunk.com/Documentation/AddOns/released/AWS/
  {
    name: 'AWS',
    indicators: [
      'eventname',
      'awsregion',
      'eventtype',
      'eventsource',
      'useridentity',
      'requestparameters',
    ],
    logTypeDetection: (line: string) => {
      const lower = line.toLowerCase();
      if (lower.includes('cloudtrail') || lower.includes('eventsource')) return 'cloudtrail';
      if (lower.includes('vpcflow') || lower.includes('flowlogstatus')) return 'cloudwatch:vpcflow';
      if (lower.includes('cloudwatch')) return 'cloudwatch';
      return 'cloudtrail'; // Default
    },
    sourcetypePrefix: 'aws',
  },

  // Microsoft Azure - Best Practice: azure:monitor:activity
  // Reference: https://github.com/splunk/splunk-azure-monitor-logs-function
  {
    name: 'Microsoft Azure',
    indicators: [
      'azure',
      'resourceid',
      'subscriptionid',
      'operationname',
      'activitylog',
      'tenantid',
    ],
    logTypeDetection: (line: string) => {
      const lower = line.toLowerCase();
      if (lower.includes('activitylog') || lower.includes('operationname'))
        return 'monitor:activity';
      if (lower.includes('diagnostics')) return 'monitor:diagnostics';
      if (lower.includes('aad') || lower.includes('signinlogs')) return 'aad:signin';
      return 'monitor:activity';
    },
    sourcetypePrefix: 'azure',
  },

  // Apache Web Server - Best Practice: apache:access, apache:error
  // Note: Legacy sourcetype access_combined is being phased out
  {
    name: 'Apache',
    indicators: ['"get ', '"post ', '"put ', '"delete ', 'apache', 'http/1.1', 'http/1.0'],
    logTypeDetection: (line: string) => {
      const lower = line.toLowerCase();
      if (lower.includes('[error]') || lower.includes('[warn]')) return 'error';
      if (line.match(/"\s*[A-Z]+\s+/)) return 'access'; // HTTP method detected
      return 'access';
    },
    sourcetypePrefix: 'apache',
  },

  // Nginx Web Server - Best Practice: nginx:plus:access, nginx:plus:error
  {
    name: 'Nginx',
    indicators: ['nginx', '"http/1.', ' - - [', 'upstream'],
    logTypeDetection: (line: string) => {
      const lower = line.toLowerCase();
      if (lower.includes('[error]') || lower.includes('[warn]')) return 'plus:error';
      return 'plus:access';
    },
    sourcetypePrefix: 'nginx',
  },

  // Microsoft Windows - Best Practice: WinEventLog:Security, WinEventLog:System
  {
    name: 'Microsoft Windows',
    indicators: [
      'microsoft-windows',
      'eventid',
      'event id',
      'eventrecordid',
      'providername',
      'keywords=',
    ],
    logTypeDetection: (line: string) => {
      const lower = line.toLowerCase();
      if (lower.includes('security') || lower.includes('audit')) return 'Security';
      if (lower.includes('system')) return 'System';
      if (lower.includes('application')) return 'Application';
      return 'Security'; // Default
    },
    sourcetypePrefix: 'WinEventLog',
  },

  // Linux Syslog - Best Practice: linux:syslog (structure-based detection)
  {
    name: 'Linux Syslog',
    indicators: [], // Detected by format pattern
    logTypeDetection: () => 'syslog',
    sourcetypePrefix: 'linux',
  },
];

function detectVendorAndPaths(
  line: string,
  fields: string[]
): { vendor: string | null; paths: string[]; sourcetype: string | null } {
  const lowerLine = line.toLowerCase();

  // Try each vendor pattern
  for (const pattern of VENDOR_PATTERNS) {
    // Check if any indicators match
    const hasIndicator =
      pattern.indicators.length === 0
        ? false
        : pattern.indicators.some((indicator) => lowerLine.includes(indicator.toLowerCase()));

    if (hasIndicator) {
      const logType = pattern.logTypeDetection?.(line) || null;

      // Build sourcetype based on vendor convention (some use underscores, most use colons)
      const separator = pattern.useUnderscoreFormat ? '_' : ':';
      const sourcetype = logType
        ? `${pattern.sourcetypePrefix}${separator}${logType}`
        : pattern.sourcetypePrefix;

      // Generate generic path suggestions based on vendor and log type
      const vendorSlug = pattern.sourcetypePrefix.toLowerCase();
      const logTypeSlug = logType?.toLowerCase().replace(/[^a-z0-9]/g, '_') || 'logs';

      const paths = [`/var/log/${vendorSlug}/${logTypeSlug}.log`, `/var/log/${vendorSlug}/*.log`];

      // Windows paths use backslashes
      if (pattern.name === 'Microsoft Windows') {
        return {
          vendor: pattern.name,
          paths: [
            `C:\\Windows\\System32\\winevt\\Logs\\${logType}.evtx`,
            'C:\\Windows\\System32\\winevt\\Logs\\*.evtx',
          ],
          sourcetype,
        };
      }

      return {
        vendor: pattern.name,
        paths,
        sourcetype,
      };
    }
  }

  // Special case: Syslog format detection (structure-based, not keyword-based)
  if (/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\w+/.test(line)) {
    return {
      vendor: 'Linux Syslog',
      paths: ['/var/log/syslog', '/var/log/messages'],
      sourcetype: 'linux:syslog',
    };
  }

  // Default: No vendor detected, suggest generic paths
  return {
    vendor: null,
    paths: ['/path/to/your/logs/*.log'],
    sourcetype: null,
  };
}

function calculateConfidence(
  timestampInfo: { format: string } | null,
  sampleType: string,
  fields: string[]
): 'high' | 'medium' | 'low' {
  let score = 0;

  if (timestampInfo) score += 2;
  if (sampleType !== 'unknown') score += 2;
  if (fields.length >= 3) score += 1;

  if (score >= 4) return 'high';
  if (score >= 2) return 'medium';
  return 'low';
}

/**
 * Generate props.conf stanza from log sample analysis
 */
export function generatePropsFromAnalysis(sourcetype: string, analysis: LogSampleAnalysis): string {
  const lines: string[] = [`[${sourcetype}]`];

  // Line merging
  if (analysis.sampleType === 'json') {
    lines.push('SHOULD_LINEMERGE = false');
  } else {
    lines.push('SHOULD_LINEMERGE = false');
  }

  lines.push(`LINE_BREAKER = ${analysis.lineBreaker}`);

  // Timestamp
  if (analysis.timeFormat) {
    if (analysis.timePrefix) {
      lines.push(`TIME_PREFIX = ${analysis.timePrefix}`);
    }
    lines.push(`TIME_FORMAT = ${analysis.timeFormat}`);
    lines.push(`MAX_TIMESTAMP_LOOKAHEAD = ${analysis.maxTimestampLookahead}`);
  }

  // KV Mode
  lines.push(`KV_MODE = ${analysis.kvMode}`);

  // Truncate
  lines.push('TRUNCATE = 999999');

  // Add comment about detected fields
  if (analysis.detectedFields.length > 0) {
    lines.push('');
    lines.push(`# Detected fields: ${analysis.detectedFields.slice(0, 10).join(', ')}`);
  }

  return lines.join('\n');
}
