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
