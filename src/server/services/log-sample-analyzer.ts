// Log Sample Analyzer - Detects timestamp formats, line breakers, and field patterns
// This eliminates guesswork by analyzing actual log samples

import type {
  LogSampleAnalysis,
  FieldExtraction,
  LogPlatform,
  LogFormat,
  SplunkInputMethod,
} from '@/types/logonboard';

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
  const fullSample = sample.trim(); // Keep full sample for multi-line JSON detection

  // Detect sample type (use full sample to handle multi-line JSON)
  const sampleType = detectSampleType(fullSample);

  // For single-line formats, use firstLine; for JSON, use fullSample
  const analyzeTarget = sampleType === 'json' ? fullSample : firstLine;

  // Detect timestamp
  const timestampInfo = detectTimestamp(analyzeTarget);

  // Detect KV mode
  const kvMode = detectKVMode(analyzeTarget, sampleType);

  // Detect fields (names only, for backward compatibility)
  const detectedFields = detectFields(analyzeTarget, sampleType);

  // Extract fields with values (new feature)
  const extractedFields = extractFieldsWithValues(analyzeTarget, sampleType);

  // Detect line breaker
  const lineBreaker = detectLineBreaker(lines);

  // Detect vendor and suggest paths
  const vendorInfo = detectVendorAndPaths(analyzeTarget);

  // Calculate confidence
  const confidence = calculateConfidence(timestampInfo, sampleType, detectedFields);

  // Detect platform and format
  const detectedPlatform = detectPlatform(sample, vendorInfo.vendor, vendorInfo.paths);
  const detectedFormat = detectFormat(sample, sampleType, vendorInfo.vendor);
  const inputMethodInfo = determineSplunkInputMethod(
    detectedPlatform,
    detectedFormat,
    vendorInfo.vendor
  );

  // Generate platform/format-aware sourcetype
  const platformAwareSourcetype = generateSourcetype(
    detectedPlatform,
    detectedFormat,
    vendorInfo.vendor,
    vendorInfo.sourcetype
  );

  return {
    timeFormat: timestampInfo?.format || null,
    timePrefix: timestampInfo?.prefix || null,
    lineBreaker,
    kvMode,
    maxTimestampLookahead: timestampInfo?.lookahead || 150,
    detectedFields,
    extractedFields,
    confidence,
    sampleType,
    rawPattern: timestampInfo?.rawMatch || null,
    suggestedPaths: vendorInfo.paths,
    detectedVendor: vendorInfo.vendor,
    suggestedSourcetype: platformAwareSourcetype, // Now uses platform/format-aware sourcetype
    // New platform/format detection
    detectedPlatform,
    detectedFormat,
    splunkInputMethod: inputMethodInfo.method,
    inputMethodNotes: inputMethodInfo.notes,
  };
}

function detectSampleType(line: string): 'json' | 'kv' | 'syslog' | 'apache' | 'csv' | 'unknown' {
  const trimmed = line.trim();

  // JSON detection (handles both single-line and multi-line formatted JSON)
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      JSON.parse(trimmed);
      return 'json';
    } catch {
      // Not valid JSON, continue with other checks
    }
  }

  // For multi-line samples, check the first line only for other formats
  const firstLine = trimmed.split('\n')[0] || '';

  // Apache Combined/Common Log Format
  if (/^\S+\s+\S+\s+\S+\s+\[.*\]\s+"[A-Z]+\s+/.test(firstLine)) {
    return 'apache';
  }

  // Syslog format
  if (/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+/.test(firstLine)) {
    return 'syslog';
  }

  // CSV detection (comma-separated with consistent field count)
  const commaCount = (firstLine.match(/,/g) || []).length;
  if (commaCount >= 3 && !firstLine.includes('=')) {
    return 'csv';
  }

  // Key=Value detection
  if (/\w+=["']?[^"'\s]+["']?/.test(firstLine)) {
    return 'kv';
  }

  return 'unknown';
}

function detectTimestamp(
  line: string
): { format: string; prefix: string | null; lookahead: number; rawMatch: string } | null {
  // Try to extract timestamp from JSON first
  if (line.trim().startsWith('{')) {
    try {
      const json = JSON.parse(line);
      // Common JSON timestamp field names
      const timestampFields = [
        'timestamp',
        '@timestamp',
        'time',
        'datetime',
        'ts',
        'eventTime',
        'eventtime',
        'created',
        'createdAt',
        'created_at',
        'date',
      ];

      for (const field of timestampFields) {
        const value = getNestedValue(json, field);
        if (value && typeof value === 'string') {
          // Try to match the timestamp value against our patterns
          for (const pattern of TIMESTAMP_PATTERNS) {
            const match = value.match(pattern.regex);
            if (match) {
              return {
                format: pattern.format,
                prefix: pattern.prefix || null,
                lookahead: pattern.lookahead,
                rawMatch: match[0],
              };
            }
          }
        }
      }
    } catch {
      // Not valid JSON, continue with string matching
    }
  }

  // Fallback to pattern matching on the full line
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

// Helper function to get nested JSON values
function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  if (!obj || typeof obj !== 'object') return undefined;
  // Support both direct keys and nested paths like "log.timestamp"
  if (path in obj) return obj[path];
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current && typeof current === 'object' && part in (current as Record<string, unknown>)) {
      current = (current as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return current;
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

// Extract fields with their sample values and types
function extractFieldsWithValues(line: string, sampleType: string): FieldExtraction[] {
  const fields: FieldExtraction[] = [];

  if (sampleType === 'json') {
    try {
      const parsed = JSON.parse(line.trim());

      // Recursively extract fields from nested JSON
      const extractNested = (obj: Record<string, unknown>, prefix = ''): void => {
        for (const [key, value] of Object.entries(obj)) {
          const fieldPath = prefix ? `${prefix}.${key}` : key;
          const fieldName = prefix ? key : key; // Top-level shows just key name
          const valueType = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;

          if (valueType === 'object' && value !== null && !Array.isArray(value)) {
            // For nested objects, add the object itself and recurse
            fields.push({
              name: fieldName,
              sampleValue: JSON.stringify(value),
              type: 'object',
              nested: !!prefix,
              path: fieldPath,
            });
            extractNested(value as Record<string, unknown>, fieldPath);
          } else if (valueType === 'array') {
            fields.push({
              name: fieldName,
              sampleValue: JSON.stringify(value),
              type: 'array',
              nested: !!prefix,
              path: fieldPath,
            });
          } else {
            // valueType is 'string', 'number', 'boolean', or 'null'
            const fieldType =
              valueType === 'string' ||
              valueType === 'number' ||
              valueType === 'boolean' ||
              valueType === 'null'
                ? valueType
                : 'string';
            fields.push({
              name: fieldName,
              sampleValue: String(value),
              type: fieldType,
              nested: !!prefix,
              path: fieldPath,
            });
          }
        }
      };

      extractNested(parsed);
      return fields.slice(0, 50); // Limit to 50 fields total
    } catch {
      return [];
    }
  }

  if (sampleType === 'kv') {
    const matches = line.match(/(\w+)=["']?([^"'\s,]+)["']?/g) || [];
    for (const match of matches.slice(0, 30)) {
      const [key, ...valueParts] = match.split('=');
      const value = valueParts.join('=').replace(/^["']|["']$/g, '');
      if (key) {
        const numValue = parseFloat(value);
        const valueType = !isNaN(numValue) && value.trim() !== '' ? 'number' : 'string';
        fields.push({
          name: key,
          sampleValue: value,
          type: valueType,
          path: key,
        });
      }
    }
    return fields;
  }

  if (sampleType === 'apache') {
    // Parse common Apache log format
    const apacheRegex =
      /^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?/;
    const match = line.match(apacheRegex);
    if (match) {
      return [
        { name: 'clientip', sampleValue: match[1] || '-', type: 'string', path: 'clientip' },
        { name: 'ident', sampleValue: match[2] || '-', type: 'string', path: 'ident' },
        { name: 'user', sampleValue: match[3] || '-', type: 'string', path: 'user' },
        { name: 'timestamp', sampleValue: match[4] || '-', type: 'string', path: 'timestamp' },
        { name: 'method', sampleValue: match[5] || '-', type: 'string', path: 'method' },
        { name: 'uri', sampleValue: match[6] || '-', type: 'string', path: 'uri' },
        { name: 'protocol', sampleValue: match[7] || '-', type: 'string', path: 'protocol' },
        { name: 'status', sampleValue: match[8] || '-', type: 'number', path: 'status' },
        { name: 'bytes', sampleValue: match[9] || '-', type: 'number', path: 'bytes' },
        { name: 'referer', sampleValue: match[10] || '-', type: 'string', path: 'referer' },
        { name: 'useragent', sampleValue: match[11] || '-', type: 'string', path: 'useragent' },
      ];
    }
    return [];
  }

  if (sampleType === 'syslog') {
    // Parse syslog format: timestamp host process[pid]: message
    const syslogRegex = /^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)(?:\[(\d+)\])?:\s*(.*)$/;
    const match = line.match(syslogRegex);
    if (match) {
      return [
        { name: 'timestamp', sampleValue: match[1] || '', type: 'string', path: 'timestamp' },
        { name: 'host', sampleValue: match[2] || '', type: 'string', path: 'host' },
        { name: 'process', sampleValue: match[3] || '', type: 'string', path: 'process' },
        { name: 'pid', sampleValue: match[4] || '', type: 'number', path: 'pid' },
        { name: 'message', sampleValue: match[5] || '', type: 'string', path: 'message' },
      ];
    }
    return [];
  }

  if (sampleType === 'csv') {
    // Basic CSV parsing
    const values = line.split(',').map((v) => v.trim().replace(/^["']|["']$/g, ''));
    return values.map((value, index) => ({
      name: `field${index + 1}`,
      sampleValue: value,
      type: !isNaN(parseFloat(value)) && value.trim() !== '' ? 'number' : 'string',
      path: `field${index + 1}`,
    }));
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

// Helper function to extract all keys from a JSON object (including nested)
function extractJsonKeys(obj: Record<string, unknown>, prefix = ''): string[] {
  const keys: string[] = [];
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      keys.push(fullKey);
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        keys.push(...extractJsonKeys(value as Record<string, unknown>, fullKey));
      }
    }
  }
  return keys;
}

function detectVendorAndPaths(line: string): {
  vendor: string | null;
  paths: string[];
  sourcetype: string | null;
} {
  const lowerLine = line.toLowerCase();

  // Try to parse as JSON for better field-based detection
  let jsonData: Record<string, unknown> | null = null;
  let jsonFields: string[] = [];
  try {
    if (line.trim().startsWith('{')) {
      jsonData = JSON.parse(line) as Record<string, unknown>;
      jsonFields = extractJsonKeys(jsonData).map((f) => f.toLowerCase());
    }
  } catch {
    // Not JSON or invalid JSON, continue with string matching
  }

  // Try each vendor pattern
  for (const pattern of VENDOR_PATTERNS) {
    // Check if any indicators match (both in raw line and JSON fields)
    const hasIndicator =
      pattern.indicators.length === 0
        ? false
        : pattern.indicators.some((indicator) => {
            const lowerIndicator = indicator.toLowerCase();
            // Check in raw line
            if (lowerLine.includes(lowerIndicator)) return true;
            // Check in JSON field names if available
            if (jsonFields.length > 0 && jsonFields.some((f) => f.includes(lowerIndicator)))
              return true;
            return false;
          });

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

/**
 * Detect the platform/OS type from log sample
 * Analyzes log content, paths, and patterns to determine the source platform
 */
function detectPlatform(sample: string, vendor: string | null, paths: string[]): LogPlatform {
  const lowerSample = sample.toLowerCase();
  const allText = `${sample} ${vendor || ''} ${paths.join(' ')}`.toLowerCase();

  // Windows indicators
  if (
    /[a-z]:\\/.test(sample) || // Drive letter paths
    /\.evtx/i.test(sample) || // Windows Event Log
    /eventlog|winevt|windows/i.test(sample) ||
    vendor === 'Microsoft Windows' ||
    paths.some((p) => /^[a-z]:\\/i.test(p))
  ) {
    return 'windows';
  }

  // Cloud platforms (check before OS since they can run on any OS)
  if (/aws|amazon|s3|ec2|lambda|cloudwatch|kinesis/.test(lowerSample) || /arn:aws/.test(sample)) {
    return 'aws';
  }

  if (
    /azure|microsoft cloud|azurewebsites|blob\.core\.windows/.test(lowerSample) ||
    /"cloud":"azure"/i.test(sample)
  ) {
    return 'azure';
  }

  if (
    /gcp|google cloud|cloud\.google|pubsub|bigquery/.test(lowerSample) ||
    /projects\/[\w-]+\//.test(sample)
  ) {
    return 'gcp';
  }

  // Container platforms
  if (/docker|container_id|container_name/.test(lowerSample) || /"container":/i.test(sample)) {
    return 'docker';
  }

  if (/kubernetes|k8s|pod_name|namespace/.test(lowerSample) || /"kubernetes":/i.test(sample)) {
    return 'kubernetes';
  }

  // Unix/Linux indicators
  if (
    /\/var\/log|\/usr\/|\/etc\/|syslog|\/home\//.test(sample) ||
    paths.some((p) => p.startsWith('/'))
  ) {
    // Try to distinguish between generic Unix and Linux
    if (/systemd|journalctl|dmesg|ubuntu|debian|centos|rhel|fedora/.test(lowerSample)) {
      return 'linux';
    }
    return 'unix'; // Generic Unix (could be Linux, BSD, Solaris, etc.)
  }

  // macOS indicators
  if (/\/Library\/Logs|\/System\/Library|darwin|macos/.test(allText)) {
    return 'macos';
  }

  // If contains cloud indicators but not specific platform
  if (/cloud|saas/.test(lowerSample)) {
    return 'cloud';
  }

  return 'unknown';
}

/**
 * Detect the log format type from sample
 * Determines the structure/format of the log data
 */
function detectFormat(sample: string, sampleType: string, vendor: string | null): LogFormat {
  const trimmed = sample.trim();
  const lowerSample = sample.toLowerCase();

  // JSON format (already detected by sampleType)
  if (sampleType === 'json' || (trimmed.startsWith('{') && trimmed.endsWith('}'))) {
    return 'json';
  }

  // XML format
  if (trimmed.startsWith('<') && trimmed.includes('</')) {
    return 'xml';
  }

  // CSV format
  if (sampleType === 'csv' || /^[^,]+,[^,]+,/.test(trimmed)) {
    return 'csv';
  }

  // CEF (Common Event Format) - starts with "CEF:"
  if (/^CEF:\d+\|/.test(trimmed)) {
    return 'cef';
  }

  // LEEF (Log Event Extended Format) - starts with "LEEF:"
  if (/^LEEF:[\d.]+\|/.test(trimmed)) {
    return 'leef';
  }

  // Windows Event Log XML format
  if (
    /<Event xmlns/.test(sample) ||
    /\.evtx|EventID|EventLog/i.test(sample) ||
    vendor === 'Microsoft Windows'
  ) {
    return 'windows-evtx';
  }

  // Syslog format (RFC 3164 or RFC 5424)
  if (
    sampleType === 'syslog' ||
    /^<\d{1,3}>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(trimmed) || // RFC 3164
    /^<\d{1,3}>\d+\s+\d{4}-\d{2}-\d{2}T/.test(trimmed) // RFC 5424
  ) {
    return 'syslog';
  }

  // Apache access/error log
  if (
    sampleType === 'apache' ||
    /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+-\s+\[/.test(trimmed) || // Apache access
    /\[client\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(sample) // Apache error
  ) {
    return 'apache';
  }

  // Nginx access/error log
  if (
    /nginx|upstream/.test(lowerSample) &&
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*"\w+\s+\/.*HTTP\/\d\.\d"/.test(sample)
  ) {
    return 'nginx';
  }

  // IIS log format
  if (
    /^#Software:|^#Version:|^#Date:/.test(trimmed) ||
    /\s+\d{3}\s+\d+\s+\d+\s+\d+$/.test(sample) // IIS log pattern
  ) {
    return 'iis';
  }

  // Key-value pairs
  if (sampleType === 'kv' || /\w+=[\w"'][^\s]*(\s+\w+=[\w"'][^\s]*){2,}/.test(sample)) {
    return 'kv';
  }

  // Custom/unstructured
  if (sampleType === 'unknown') {
    return 'unknown';
  }

  return 'custom';
}

/**
 * Generate appropriate sourcetype based on detected platform and format
 * This ensures consistency between what we detect and what we configure
 */
function generateSourcetype(
  platform: LogPlatform,
  format: LogFormat,
  vendor: string | null,
  fallbackSourcetype: string | null
): string {
  // AWS platform
  if (platform === 'aws') {
    if (vendor?.toLowerCase().includes('cloudwatch')) return 'aws:cloudwatch';
    if (vendor?.toLowerCase().includes('s3')) return 'aws:s3';
    if (vendor?.toLowerCase().includes('cloudtrail')) return 'aws:cloudtrail';
    if (vendor?.toLowerCase().includes('vpc')) return 'aws:cloudwatch:vpcflow';
    if (format === 'json') return 'aws:cloudwatch';
    return 'aws:log';
  }

  // Azure platform
  if (platform === 'azure') {
    if (vendor?.toLowerCase().includes('activity')) return 'azure:activity';
    if (vendor?.toLowerCase().includes('diagnostic')) return 'azure:diagnostic';
    if (format === 'json') return 'azure:log:json';
    return 'azure:log';
  }

  // GCP platform
  if (platform === 'gcp') {
    if (vendor?.toLowerCase().includes('audit')) return 'gcp:audit';
    if (vendor?.toLowerCase().includes('pubsub')) return 'gcp:pubsub';
    if (format === 'json') return 'gcp:log:json';
    return 'gcp:log';
  }

  // Docker platform
  if (platform === 'docker') {
    if (format === 'json') return 'docker:container:json';
    return 'docker:container';
  }

  // Kubernetes platform
  if (platform === 'kubernetes') {
    if (format === 'json') return 'kube:container:json';
    return 'kube:container';
  }

  // Windows platform
  if (platform === 'windows') {
    if (format === 'windows-evtx') return 'WinEventLog';
    if (vendor?.toLowerCase().includes('security')) return 'WinEventLog:Security';
    if (vendor?.toLowerCase().includes('system')) return 'WinEventLog:System';
    if (vendor?.toLowerCase().includes('application')) return 'WinEventLog:Application';
    return 'windows:log';
  }

  // Linux/Unix platform
  if (platform === 'linux' || platform === 'unix') {
    if (format === 'syslog') return 'syslog';
    if (vendor?.toLowerCase().includes('auth')) return 'linux:auth';
    if (vendor?.toLowerCase().includes('secure')) return 'linux:secure';
    return 'linux:log';
  }

  // macOS platform
  if (platform === 'macos') {
    if (format === 'syslog') return 'macos:syslog';
    return 'macos:log';
  }

  // Format-based sourcetypes (when platform is unknown or cloud/generic)
  if (format === 'cef') return 'cef';
  if (format === 'leef') return 'leef';
  if (format === 'apache') return 'access_combined';
  if (format === 'nginx') return 'nginx:access';
  if (format === 'iis') return 'iis';
  if (format === 'csv') return 'csv';
  if (format === 'xml') return 'xml';
  if (format === 'json' && platform === 'cloud') return 'cloud:json';
  if (format === 'json') return 'json';

  // Fallback to vendor-detected sourcetype or generic
  return fallbackSourcetype || 'generic_log';
}

/**
 * Determine the best Splunk input method based on platform and format
 * Returns the input method and optional notes for special handling
 */
function determineSplunkInputMethod(
  platform: LogPlatform,
  format: LogFormat,
  vendor: string | null
): { method: SplunkInputMethod; notes?: string } {
  // Cloud platforms typically use their specific collectors
  if (platform === 'aws') {
    if (format === 'json') {
      return {
        method: 'cloudwatch',
        notes:
          'For CloudWatch Logs, use the Splunk Add-on for AWS. For S3 logs, configure S3 inputs. For real-time streaming, consider Kinesis Firehose.',
      };
    }
    return {
      method: 's3',
      notes: 'Use the Splunk Add-on for AWS to configure S3 inputs for archived logs.',
    };
  }

  if (platform === 'azure') {
    return {
      method: 'azure-blob',
      notes:
        'Use the Splunk Add-on for Microsoft Cloud Services. Configure Azure Blob Storage inputs or Azure Event Hub for real-time streaming.',
    };
  }

  if (platform === 'gcp') {
    return {
      method: 'gcp-pubsub',
      notes:
        'Use the Splunk Add-on for Google Cloud Platform. Configure Pub/Sub subscriptions or Cloud Storage buckets.',
    };
  }

  // Windows-specific methods
  if (platform === 'windows') {
    if (format === 'windows-evtx') {
      return {
        method: 'wmi',
        notes:
          'For Windows Event Logs, use WMI inputs in inputs.conf. Consider using the Splunk Universal Forwarder on Windows hosts.',
      };
    }
    if (format === 'json' || format === 'xml') {
      return {
        method: 'powershell',
        notes:
          'For structured data on Windows, consider using PowerShell scripted inputs or the Splunk HTTP Event Collector (HEC).',
      };
    }
  }

  // JSON and structured formats - HEC is often better
  if (format === 'json' || format === 'xml') {
    return {
      method: 'hec',
      notes:
        '⚠️ For JSON/XML logs, consider using HTTP Event Collector (HEC) instead of file monitoring for better performance and structure preservation. Configure HEC endpoints in inputs.conf.',
    };
  }

  // Docker/Kubernetes - typically use logging drivers or collectors
  if (platform === 'docker' || platform === 'kubernetes') {
    return {
      method: 'hec',
      notes:
        'For container logs, use Docker logging driver or Kubernetes DaemonSet with HEC. Alternatively, use Splunk Connect for Kubernetes.',
    };
  }

  // CEF/LEEF formats - often received via syslog
  if (format === 'cef' || format === 'leef') {
    return {
      method: 'scripted',
      notes:
        'CEF/LEEF logs are often received via syslog. Configure syslog inputs or use monitor stanza if reading from files.',
    };
  }

  // Default: standard file monitoring
  return {
    method: 'monitor',
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
