import sourcetypeMappings from '@/knowledge-base/sourcetype-mappings.json';
import propsTemplates from '@/knowledge-base/props-templates.json';
import sensitivePatterns from '@/knowledge-base/sensitive-patterns.json';
import vendorPatterns from '@/knowledge-base/vendor-patterns.json';
import type { SourcetypeMapping, PropsTemplate, SensitivePattern } from '@/types/logonboard';

// Knowledge Base Service - Provides access to all KB data

export function getSourcetypeMappings() {
  return sourcetypeMappings;
}

export function getPropsTemplates() {
  return propsTemplates.templates as Record<string, PropsTemplate>;
}

export function getSensitivePatterns() {
  return sensitivePatterns.patterns as Record<string, SensitivePattern>;
}

export function getRiskLevels() {
  return sensitivePatterns.risk_levels;
}

export function getVendorPatterns() {
  return vendorPatterns.vendors;
}

export function getSourcetypeByFilename(filename: string): SourcetypeMapping | null {
  const mappings = sourcetypeMappings.filename_patterns as Record<string, SourcetypeMapping>;
  const lowerFilename = filename.toLowerCase();

  // Exact match first
  if (mappings[lowerFilename]) {
    return mappings[lowerFilename];
  }

  // Partial match (e.g., "access.log.1" should match "access.log")
  for (const [pattern, mapping] of Object.entries(mappings)) {
    if (lowerFilename.startsWith(pattern) || lowerFilename.includes(pattern)) {
      return mapping;
    }
  }

  return null;
}

export function getSourcetypeByDirectory(directory: string): SourcetypeMapping | null {
  const mappings = sourcetypeMappings.directory_patterns as Record<string, SourcetypeMapping>;
  const normalizedDir = directory.replace(/\\/g, '/').toLowerCase();

  for (const [pattern, mapping] of Object.entries(mappings)) {
    const normalizedPattern = pattern.replace(/\\/g, '/').toLowerCase();
    if (normalizedDir.includes(normalizedPattern)) {
      return mapping;
    }
  }

  return null;
}

export function getSourcetypeByExtension(extension: string): SourcetypeMapping | null {
  const mappings = sourcetypeMappings.extension_patterns as Record<string, SourcetypeMapping>;
  const lowerExt = extension.toLowerCase();

  return mappings[lowerExt] || null;
}

export function getPropsTemplate(sourcetype: string): PropsTemplate {
  const templates = getPropsTemplates();
  return templates[sourcetype] || templates['_default'];
}

export function detectVendor(path: string): { vendor: string; sourcetype: string } | null {
  const vendors = getVendorPatterns();
  const normalizedPath = path.replace(/\\/g, '/').toLowerCase();

  for (const [vendorName, vendorConfig] of Object.entries(vendors)) {
    // Check paths
    for (const vendorPath of vendorConfig.paths) {
      const normalizedVendorPath = vendorPath.replace(/\\/g, '/').toLowerCase();
      if (normalizedPath.includes(normalizedVendorPath)) {
        const defaultSourcetype = Object.values(vendorConfig.sourcetypes)[0] || 'generic';
        return { vendor: vendorName, sourcetype: defaultSourcetype };
      }
    }

    // Check files
    const filename = path.split(/[/\\]/).pop()?.toLowerCase() || '';
    for (const vendorFile of vendorConfig.files) {
      const pattern = vendorFile.replace('*', '.*');
      if (new RegExp(pattern, 'i').test(filename)) {
        const defaultSourcetype = Object.values(vendorConfig.sourcetypes)[0] || 'generic';
        return { vendor: vendorName, sourcetype: defaultSourcetype };
      }
    }
  }

  return null;
}
