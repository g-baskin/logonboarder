// Curated Cribl Stream Functions Knowledge Base
import type { CriblDocumentation } from '../types';

/**
 * Curated knowledge base for Cribl Stream functions
 * Based on official Cribl documentation
 */
export const criblFunctionsKnowledgeBase: Omit<
  CriblDocumentation,
  'id' | 'createdAt' | 'updatedAt'
>[] = [
  {
    type: 'cribl',
    title: 'Auto Timestamp Function',
    content:
      "The Auto Timestamp function automatically extracts timestamps from events using strptime format strings. It supports multiple timestamp formats and can handle timezone information. This is the Cribl equivalent of Splunk's TIME_FORMAT and TIME_PREFIX settings.",
    url: 'https://docs.cribl.io/stream/auto-timestamp-function',
    section: 'overview',
    metadata: {
      primaryUse: 'Extract timestamps from events',
      splunkEquivalent: 'TIME_FORMAT, TIME_PREFIX, MAX_TIMESTAMP_LOOKAHEAD',
      keyFields: 'srcField, format, timezone, maxLen',
    },
    functionType: 'auto_timestamp',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Auto Timestamp: Configuration Fields',
    content:
      'srcField: Field containing timestamp (default: _raw). format: Array of strptime format strings to try (e.g., ["%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"]). timezone: Timezone for timestamp interpretation. maxLen: Maximum characters to search for timestamp (similar to MAX_TIMESTAMP_LOOKAHEAD).',
    url: 'https://docs.cribl.io/stream/auto-timestamp-function',
    section: 'configuration',
    metadata: {
      example: JSON.stringify(
        {
          srcField: '_raw',
          format: ['%Y-%m-%d %H:%M:%S', '%s'],
          timezone: 'UTC',
          maxLen: 150,
        },
        null,
        2
      ),
    },
    functionType: 'auto_timestamp',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Regex Extract Function',
    content:
      "The Regex Extract function extracts fields from events using regular expressions with named capture groups. This is the Cribl equivalent of Splunk's EXTRACT settings. Uses standard regex syntax with (?<fieldname>pattern) for named captures.",
    url: 'https://docs.cribl.io/stream/regex-extract-function',
    section: 'overview',
    metadata: {
      primaryUse: 'Extract fields using regex patterns',
      splunkEquivalent: 'EXTRACT-<name>, REPORT-<name>',
      keyFields: 'srcField, regex, overwrite',
    },
    functionType: 'regex_extract',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Regex Extract: Configuration Fields',
    content:
      'srcField: Source field to extract from (default: _raw). regex: Regular expression with named capture groups using (?<name>pattern) syntax. overwrite: Whether to overwrite existing fields (default: false). iterations: Number of times to apply regex (default: 1 for first match, 100 for all matches).',
    url: 'https://docs.cribl.io/stream/regex-extract-function',
    section: 'configuration',
    metadata: {
      example: JSON.stringify(
        {
          srcField: '_raw',
          regex: /user=(?<username>\w+)\s+ip=(?<ip_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.source,
          overwrite: false,
        },
        null,
        2
      ),
      note: 'Cribl uses (?<name>) syntax, Splunk uses (?P<name>) syntax',
    },
    functionType: 'regex_extract',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Parser Function',
    content:
      "The Parser function automatically parses structured data formats like JSON, CSV, key-value pairs, and more. It's similar to Splunk's KV_MODE setting but more flexible. Supports multiple parsing modes and can handle nested structures.",
    url: 'https://docs.cribl.io/stream/parser-function',
    section: 'overview',
    metadata: {
      primaryUse: 'Parse structured log formats',
      splunkEquivalent: 'KV_MODE, INDEXED_EXTRACTIONS',
      keyFields: 'mode, srcField, dstField',
    },
    functionType: 'parser',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Parser: Configuration Fields',
    content:
      'mode: Parsing mode - json, csv, kv (key-value), delim (delimited), clf (common log format), elff (extended log file format). srcField: Field to parse (default: _raw). dstField: Where to store parsed fields (default: root level). kvDelimiter: Delimiter for key-value pairs (default: =). pairDelimiter: Delimiter between pairs (default: space).',
    url: 'https://docs.cribl.io/stream/parser-function',
    section: 'configuration',
    metadata: {
      example: JSON.stringify(
        { mode: 'json', srcField: '_raw', dstField: '', keep: ['_raw'] },
        null,
        2
      ),
      kvExample: JSON.stringify(
        {
          mode: 'kv',
          srcField: '_raw',
          kvDelimiter: '=',
          pairDelimiter: ' ',
        },
        null,
        2
      ),
    },
    functionType: 'parser',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Event Breaker Function',
    content:
      "The Event Breaker function controls how Cribl splits incoming data into individual events. This is equivalent to Splunk's SHOULD_LINEMERGE, LINE_BREAKER, and event breaking settings. Supports regex patterns, JSON arrays, and timestamp-based breaking.",
    url: 'https://docs.cribl.io/stream/event-breaker-function',
    section: 'overview',
    metadata: {
      primaryUse: 'Define event boundaries',
      splunkEquivalent: 'SHOULD_LINEMERGE, LINE_BREAKER, BREAK_ONLY_BEFORE',
      keyFields: 'rule, eventDelimiterRegex, maxEventBytes',
    },
    functionType: 'event_breaker',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Event Breaker: Configuration Fields',
    content:
      'rule: Breaking rule name. eventDelimiterRegex: Regex pattern to identify event boundaries (similar to LINE_BREAKER). maxEventBytes: Maximum event size in bytes (similar to TRUNCATE). timestampAnchorRegex: Pattern to identify timestamp for event grouping. eventBreakerRegex: Alternative to eventDelimiterRegex for complex patterns.',
    url: 'https://docs.cribl.io/stream/event-breaker-function',
    section: 'configuration',
    metadata: {
      example: JSON.stringify(
        {
          rule: 'custom',
          eventDelimiterRegex: /[\r\n]+/.source,
          maxEventBytes: 51200,
        },
        null,
        2
      ),
      note: 'For single-line events (SHOULD_LINEMERGE=false), Cribl handles this automatically - no Event Breaker needed',
    },
    functionType: 'event_breaker',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Mask Function',
    content:
      "The Mask function redacts or replaces sensitive data in events using regex patterns. This is equivalent to Splunk's SEDCMD for data masking. Supports multiple masking rules and replacement formats.",
    url: 'https://docs.cribl.io/stream/mask-function',
    section: 'overview',
    metadata: {
      primaryUse: 'Redact sensitive information',
      splunkEquivalent: 'SEDCMD-<name>, transforms.conf MASK',
      keyFields: 'rules, maskChar, depth',
    },
    functionType: 'mask',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Mask: Configuration Fields',
    content:
      'rules: Array of masking rules with regex and replacement. matchRegex: Pattern to match sensitive data. replaceExpr: Expression or string to replace matched data. maskChar: Character to use for masking (default: X). depth: How many levels deep to search in nested objects.',
    url: 'https://docs.cribl.io/stream/mask-function',
    section: 'configuration',
    metadata: {
      example: JSON.stringify(
        {
          rules: [
            {
              matchRegex: /\d{3}-\d{2}-\d{4}/.source,
              replaceExpr: 'XXX-XX-XXXX',
            },
            { matchRegex: /\d{16}/.source, replaceExpr: 'XXXXXXXXXXXXXXXX' },
          ],
        },
        null,
        2
      ),
    },
    functionType: 'mask',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Eval Function',
    content:
      "The Eval function creates, modifies, or removes fields using JavaScript expressions. This is more powerful than Splunk's eval command and can be used to transform data, perform calculations, or implement complex business logic.",
    url: 'https://docs.cribl.io/stream/eval-function',
    section: 'overview',
    metadata: {
      primaryUse: 'Create or modify fields with expressions',
      splunkEquivalent: 'eval at search time, calculated fields',
      keyFields: 'add, remove, keep',
    },
    functionType: 'eval',
    configSection: 'functions',
  },
  {
    type: 'cribl',
    title: 'Eval: Configuration Fields',
    content:
      'add: Array of field definitions with name and JavaScript expression. remove: Array of field names to remove. keep: Array of field names to keep (removes all others). Example: {name: "dest", value: "C.host || \"unknown\""} creates a "dest" field.',
    url: 'https://docs.cribl.io/stream/eval-function',
    section: 'configuration',
    metadata: {
      example: JSON.stringify(
        {
          add: [
            { name: 'dest', value: 'C.host' },
            { name: 'severity_num', value: 'C.severity === "high" ? 3 : 1' },
          ],
        },
        null,
        2
      ),
      note: 'Use C.fieldname to reference event fields in expressions',
    },
    functionType: 'eval',
    configSection: 'functions',
  },
];
