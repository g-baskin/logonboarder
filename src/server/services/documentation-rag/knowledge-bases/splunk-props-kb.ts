// Curated Splunk props.conf Knowledge Base
import type { SplunkDocumentation } from '../types';

/**
 * Curated knowledge base for Splunk props.conf settings
 * Based on official Splunk documentation
 */
export const splunkPropsKnowledgeBase: Omit<
  SplunkDocumentation,
  'id' | 'createdAt' | 'updatedAt'
>[] = [
  {
    type: 'splunk',
    title: 'props.conf: SHOULD_LINEMERGE',
    content:
      'SHOULD_LINEMERGE controls whether Splunk combines multiple lines into a single event. When set to false, Splunk treats each line as a separate event. When set to true, Splunk uses LINE_BREAKER or BREAK_ONLY_BEFORE to determine event boundaries. Default: true.',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'SHOULD_LINEMERGE',
    metadata: {
      configFile: 'props.conf',
      setting: 'SHOULD_LINEMERGE',
      defaultValue: 'true',
      example: 'SHOULD_LINEMERGE = false',
      useCases: 'Set to false for JSON logs, CSV files, or any single-line event format',
    },
    configFile: 'props.conf',
    setting: 'SHOULD_LINEMERGE',
  },
  {
    type: 'splunk',
    title: 'props.conf: LINE_BREAKER',
    content:
      'LINE_BREAKER specifies a regular expression that determines where Splunk splits the incoming data stream into individual events. This setting is used when SHOULD_LINEMERGE = true. The regex should match the characters between events (typically newlines or specific delimiters). The pattern must contain a capturing group.',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'LINE_BREAKER',
    metadata: {
      configFile: 'props.conf',
      setting: 'LINE_BREAKER',
      defaultValue: '([\\r\\n]+)',
      example: 'LINE_BREAKER = ([\\r\\n]+)',
      useCases:
        'Use for multi-line events or custom event boundaries. The capturing group specifies what to remove between events.',
    },
    configFile: 'props.conf',
    setting: 'LINE_BREAKER',
  },
  {
    type: 'splunk',
    title: 'props.conf: TIME_FORMAT',
    content:
      'TIME_FORMAT specifies the strptime format string that Splunk uses to extract the timestamp from events. This defines the format of the timestamp in your log data (e.g., %Y-%m-%d %H:%M:%S for "2024-01-15 14:30:00").',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'TIME_FORMAT',
    metadata: {
      configFile: 'props.conf',
      setting: 'TIME_FORMAT',
      defaultValue: 'auto (Splunk auto-detects)',
      example: 'TIME_FORMAT = %Y-%m-%d %H:%M:%S',
      useCases:
        'Required for non-standard timestamp formats. Common formats: %Y-%m-%d %H:%M:%S, %d/%b/%Y:%H:%M:%S, %s (epoch)',
    },
    configFile: 'props.conf',
    setting: 'TIME_FORMAT',
  },
  {
    type: 'splunk',
    title: 'props.conf: TIME_PREFIX',
    content:
      'TIME_PREFIX is a regular expression that identifies the location of the timestamp in your event data. Splunk searches for this pattern and then applies TIME_FORMAT immediately after it to extract the timestamp.',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'TIME_PREFIX',
    metadata: {
      configFile: 'props.conf',
      setting: 'TIME_PREFIX',
      defaultValue: 'auto',
      example: 'TIME_PREFIX = ^\\[',
      useCases:
        'Use when timestamp is not at the start of the line or has a specific prefix. Example: TIME_PREFIX = timestamp= for "timestamp=2024-01-15..."',
    },
    configFile: 'props.conf',
    setting: 'TIME_PREFIX',
  },
  {
    type: 'splunk',
    title: 'props.conf: MAX_TIMESTAMP_LOOKAHEAD',
    content:
      'MAX_TIMESTAMP_LOOKAHEAD specifies how many characters into an event Splunk should look for a timestamp. This improves performance by limiting how far Splunk searches for timestamps.',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'MAX_TIMESTAMP_LOOKAHEAD',
    metadata: {
      configFile: 'props.conf',
      setting: 'MAX_TIMESTAMP_LOOKAHEAD',
      defaultValue: '128',
      example: 'MAX_TIMESTAMP_LOOKAHEAD = 32',
      useCases:
        'Set to the maximum expected position of timestamp in your events. Lower values improve performance.',
    },
    configFile: 'props.conf',
    setting: 'MAX_TIMESTAMP_LOOKAHEAD',
  },
  {
    type: 'splunk',
    title: 'props.conf: KV_MODE',
    content:
      'KV_MODE controls automatic key-value pair extraction at search time. Values: none (no auto-extraction), auto (automatic extraction), json (treat as JSON), xml (treat as XML), multi (extract both KV and JSON).',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'KV_MODE',
    metadata: {
      configFile: 'props.conf',
      setting: 'KV_MODE',
      defaultValue: 'auto',
      example: 'KV_MODE = json',
      useCases:
        'Set to "json" for JSON logs, "none" to disable automatic extraction, "auto" for key=value pairs',
    },
    configFile: 'props.conf',
    setting: 'KV_MODE',
  },
  {
    type: 'splunk',
    title: 'props.conf: TRUNCATE',
    content:
      'TRUNCATE specifies the maximum length of an event in bytes. Events longer than this will be truncated. Use this to prevent extremely large events from consuming excessive resources.',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'TRUNCATE',
    metadata: {
      configFile: 'props.conf',
      setting: 'TRUNCATE',
      defaultValue: '10000',
      example: 'TRUNCATE = 50000',
      useCases:
        'Increase for logs with large events (stack traces, XML). Default 10KB may be too small for some logs.',
    },
    configFile: 'props.conf',
    setting: 'TRUNCATE',
  },
  {
    type: 'splunk',
    title: 'props.conf: EXTRACT',
    content:
      'EXTRACT-<name> defines field extractions using regular expressions. The regex should use named capture groups in Python format: (?P<fieldname>pattern). These extractions run at search time or index time depending on configuration.',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'EXTRACT',
    metadata: {
      configFile: 'props.conf',
      setting: 'EXTRACT-<name>',
      defaultValue: 'none',
      example: 'EXTRACT-user = user=(?P<username>\\w+)',
      useCases: 'Extract fields from unstructured logs. Use named capture groups for field names.',
    },
    configFile: 'props.conf',
    setting: 'EXTRACT',
  },
  {
    type: 'splunk',
    title: 'props.conf: SEDCMD',
    content:
      'SEDCMD-<name> applies sed (stream editor) commands to modify raw event data before indexing. Useful for masking sensitive data, removing unwanted characters, or standardizing formats. Format: s/pattern/replacement/flags',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'SEDCMD',
    metadata: {
      configFile: 'props.conf',
      setting: 'SEDCMD-<name>',
      defaultValue: 'none',
      example: 'SEDCMD-mask_ssn = s/\\d{3}-\\d{2}-\\d{4}/XXX-XX-XXXX/g',
      useCases: 'Mask sensitive data (SSN, credit cards), remove characters, standardize formats',
    },
    configFile: 'props.conf',
    setting: 'SEDCMD',
  },
  {
    type: 'splunk',
    title: 'props.conf: TRANSFORMS',
    content:
      'TRANSFORMS-<name> references one or more transforms.conf stanzas that perform operations like field extraction, routing, or masking. Multiple transforms can be chained by comma-separating their names.',
    url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf',
    section: 'TRANSFORMS',
    metadata: {
      configFile: 'props.conf',
      setting: 'TRANSFORMS-<name>',
      defaultValue: 'none',
      example: 'TRANSFORMS-routing = route_to_index, extract_fields',
      useCases: 'Apply transforms.conf rules for routing, field extraction, or data masking',
    },
    configFile: 'props.conf',
    setting: 'TRANSFORMS',
  },
];
