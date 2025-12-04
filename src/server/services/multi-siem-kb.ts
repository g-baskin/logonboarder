import logTypes from '@/knowledge-base/log-types.json';
import type { SIEM } from '@/types/logonboard';

// Multi-SIEM Knowledge Base Service
// Sources:
// - Splunk: https://splunkbase.splunk.com/app/1621 (CIM v6.3.0)
// - Elastic: https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-ecs.html
// - Sentinel: https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference
// - QRadar: https://www.ibm.com/docs/en/dsm
// - Cribl: https://docs.cribl.io/stream/packs/

export interface LogTypeDefinition {
  category: string;
  description: string;
  filenames: string[];
  directories?: string[];
  extensions?: string[];
  siem: {
    splunk?: SplunkMapping;
    elastic?: ElasticMapping;
    sentinel?: SentinelMapping;
    qradar?: QRadarMapping;
    cribl?: CriblMapping;
  };
}

export interface SplunkMapping {
  sourcetype: string;
  index: string;
  app?: string;
}

export interface ElasticMapping {
  module: string;
  fileset?: string;
  input?: string;
  channel?: string;
  index: string;
}

export interface SentinelMapping {
  table: string;
  connector: string;
}

export interface QRadarMapping {
  logSourceType: string;
  dsm: string;
}

export interface CriblMapping {
  sourcetype: string;
  pack: string;
}

export interface SIEMConfig {
  sourcetype: string;
  index: string;
  category: string;
  app?: string;
  // Elastic-specific
  module?: string;
  fileset?: string;
  // Sentinel-specific
  table?: string;
  connector?: string;
  // QRadar-specific
  logSourceType?: string;
  dsm?: string;
  // Cribl-specific
  pack?: string;
}

const logTypesData = logTypes.logTypes as Record<string, LogTypeDefinition>;

/**
 * Get all log types from the unified knowledge base
 */
export function getAllLogTypes(): Record<string, LogTypeDefinition> {
  return logTypesData;
}

/**
 * Find log type by filename
 */
export function findLogTypeByFilename(
  filename: string
): { logType: string; definition: LogTypeDefinition } | null {
  const lowerFilename = filename.toLowerCase();

  for (const [logType, def] of Object.entries(logTypesData)) {
    for (const pattern of def.filenames) {
      const lowerPattern = pattern.toLowerCase();
      // Handle wildcards like "u_ex*.log" or "*-json.log"
      if (lowerPattern.includes('*')) {
        const regex = new RegExp('^' + lowerPattern.replace(/\*/g, '.*') + '$', 'i');
        if (regex.test(lowerFilename)) {
          return { logType, definition: def };
        }
      } else if (lowerFilename === lowerPattern || lowerFilename.startsWith(lowerPattern)) {
        return { logType, definition: def };
      }
    }
  }

  return null;
}

/**
 * Find log type by directory path
 */
export function findLogTypeByDirectory(
  directory: string
): { logType: string; definition: LogTypeDefinition } | null {
  const normalizedDir = directory.replace(/\\/g, '/').toLowerCase();

  for (const [logType, def] of Object.entries(logTypesData)) {
    if (!def.directories) continue;

    for (const dir of def.directories) {
      const normalizedPattern = dir.replace(/\\/g, '/').toLowerCase();
      if (normalizedDir.includes(normalizedPattern)) {
        return { logType, definition: def };
      }
    }
  }

  return null;
}

/**
 * Find log type by file extension
 */
export function findLogTypeByExtension(
  extension: string
): { logType: string; definition: LogTypeDefinition } | null {
  const lowerExt = extension.toLowerCase();

  for (const [logType, def] of Object.entries(logTypesData)) {
    if (!def.extensions) continue;

    if (def.extensions.includes(lowerExt)) {
      return { logType, definition: def };
    }
  }

  return null;
}

/**
 * Get SIEM-specific configuration for a log type
 */
export function getSIEMConfig(logType: string, siem: SIEM): SIEMConfig | null {
  const def = logTypesData[logType];
  if (!def) return null;

  const siemConfig = def.siem[siem];
  if (!siemConfig) return null;

  switch (siem) {
    case 'splunk': {
      const cfg = siemConfig as SplunkMapping;
      return {
        sourcetype: cfg.sourcetype,
        index: cfg.index,
        category: def.category,
        app: cfg.app,
      };
    }
    case 'elastic': {
      const cfg = siemConfig as ElasticMapping;
      return {
        sourcetype: cfg.module,
        index: cfg.index,
        category: def.category,
        module: cfg.module,
        fileset: cfg.fileset,
      };
    }
    case 'sentinel': {
      const cfg = siemConfig as SentinelMapping;
      return {
        sourcetype: cfg.table,
        index: cfg.table,
        category: def.category,
        table: cfg.table,
        connector: cfg.connector,
      };
    }
    case 'qradar': {
      const cfg = siemConfig as QRadarMapping;
      return {
        sourcetype: cfg.logSourceType,
        index: 'default',
        category: def.category,
        logSourceType: cfg.logSourceType,
        dsm: cfg.dsm,
      };
    }
    case 'cribl': {
      const cfg = siemConfig as CriblMapping;
      return {
        sourcetype: cfg.sourcetype,
        index: 'default',
        category: def.category,
        pack: cfg.pack,
      };
    }
    default:
      return null;
  }
}

/**
 * Analyze a path and return SIEM-specific configuration
 */
export function analyzePathForSIEM(
  path: string,
  siem: SIEM
): {
  logType: string;
  config: SIEMConfig;
  confidence: 'high' | 'medium' | 'low';
  matchType: string;
} | null {
  const normalizedPath = path.replace(/\\/g, '/');
  const parts = normalizedPath.split('/');
  const filename = parts.pop() || '';
  const directory = parts.join('/');
  const extMatch = filename.match(/\.([^.]+)$/);
  const extension = extMatch ? `.${extMatch[1]}` : '';

  // Priority 1: Filename match (high confidence)
  const filenameMatch = findLogTypeByFilename(filename);
  if (filenameMatch) {
    const config = getSIEMConfig(filenameMatch.logType, siem);
    if (config) {
      return { logType: filenameMatch.logType, config, confidence: 'high', matchType: 'filename' };
    }
  }

  // Priority 2: Directory match (medium confidence)
  const directoryMatch = findLogTypeByDirectory(directory);
  if (directoryMatch) {
    const config = getSIEMConfig(directoryMatch.logType, siem);
    if (config) {
      return {
        logType: directoryMatch.logType,
        config,
        confidence: 'medium',
        matchType: 'directory',
      };
    }
  }

  // Priority 3: Extension match (medium confidence)
  if (extension) {
    const extensionMatch = findLogTypeByExtension(extension);
    if (extensionMatch) {
      const config = getSIEMConfig(extensionMatch.logType, siem);
      if (config) {
        return {
          logType: extensionMatch.logType,
          config,
          confidence: 'medium',
          matchType: 'extension',
        };
      }
    }
  }

  return null;
}

/**
 * Get knowledge base metadata
 */
export function getKBMetadata() {
  return logTypes.$meta;
}

/**
 * Get supported SIEMs
 */
export function getSupportedSIEMs(): SIEM[] {
  return ['splunk', 'elastic', 'sentinel', 'qradar', 'cribl'];
}

/**
 * Get log types by category
 */
export function getLogTypesByCategory(category: string): Record<string, LogTypeDefinition> {
  const result: Record<string, LogTypeDefinition> = {};

  for (const [logType, def] of Object.entries(logTypesData)) {
    if (def.category === category) {
      result[logType] = def;
    }
  }

  return result;
}

/**
 * Get all categories
 */
export function getAllCategories(): string[] {
  const categories = new Set<string>();

  for (const def of Object.values(logTypesData)) {
    categories.add(def.category);
  }

  return Array.from(categories).sort();
}
