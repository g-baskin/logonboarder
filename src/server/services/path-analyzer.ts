import type { PathAnalysisResult } from '@/types/logonboard';
import {
  getSourcetypeByFilename,
  getSourcetypeByDirectory,
  getSourcetypeByExtension,
  detectVendor,
} from './knowledge-base';

// Path Analysis Engine - Classifies log paths without requiring samples

export function parsePath(path: string): {
  filename: string;
  directory: string;
  extension: string;
} {
  // Normalize path separators
  const normalizedPath = path.replace(/\\/g, '/');
  const parts = normalizedPath.split('/');
  const filename = parts.pop() || '';
  const directory = parts.join('/');
  const extMatch = filename.match(/\.([^.]+)$/);
  const extension = extMatch ? `.${extMatch[1]}` : '';

  return { filename, directory, extension };
}

export function analyzePath(path: string): PathAnalysisResult {
  const { filename, directory, extension } = parsePath(path);

  // Priority 1: Filename matching (highest confidence)
  const filenameMatch = getSourcetypeByFilename(filename);
  if (filenameMatch) {
    return {
      path,
      filename,
      directory,
      extension,
      sourcetype: filenameMatch.sourcetype,
      index: filenameMatch.index,
      category: filenameMatch.category,
      confidence: 'high',
      matchType: 'filename',
    };
  }

  // Priority 2: Vendor detection
  const vendorMatch = detectVendor(path);
  if (vendorMatch) {
    return {
      path,
      filename,
      directory,
      extension,
      sourcetype: vendorMatch.sourcetype,
      index: 'main', // Default, can be refined
      category: 'vendor',
      confidence: 'high',
      matchType: 'vendor',
      vendor: vendorMatch.vendor,
    };
  }

  // Priority 3: Directory pattern matching
  const directoryMatch = getSourcetypeByDirectory(directory);
  if (directoryMatch) {
    return {
      path,
      filename,
      directory,
      extension,
      sourcetype: directoryMatch.sourcetype,
      index: directoryMatch.index,
      category: directoryMatch.category,
      confidence: 'medium',
      matchType: 'directory',
    };
  }

  // Priority 4: Extension-based matching
  const extensionMatch = getSourcetypeByExtension(extension);
  if (extensionMatch) {
    return {
      path,
      filename,
      directory,
      extension,
      sourcetype: extensionMatch.sourcetype,
      index: extensionMatch.index,
      category: extensionMatch.category,
      confidence: 'medium',
      matchType: 'extension',
    };
  }

  // Priority 5: Fallback - generic sourcetype
  return {
    path,
    filename,
    directory,
    extension,
    sourcetype: inferSourcetypeFromFilename(filename),
    index: 'main',
    category: 'unknown',
    confidence: 'low',
    matchType: 'fallback',
  };
}

export function analyzePaths(paths: string[]): PathAnalysisResult[] {
  return paths
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .map(analyzePath);
}

function inferSourcetypeFromFilename(filename: string): string {
  // Try to create a reasonable sourcetype from the filename
  const baseName = filename.replace(/\.[^.]+$/, ''); // Remove extension
  const sanitized = baseName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');

  return sanitized || 'generic_log';
}

export function groupBySourcetype(
  results: PathAnalysisResult[]
): Map<string, PathAnalysisResult[]> {
  const grouped = new Map<string, PathAnalysisResult[]>();

  for (const result of results) {
    const existing = grouped.get(result.sourcetype) || [];
    existing.push(result);
    grouped.set(result.sourcetype, existing);
  }

  return grouped;
}

export function groupByIndex(results: PathAnalysisResult[]): Map<string, PathAnalysisResult[]> {
  const grouped = new Map<string, PathAnalysisResult[]>();

  for (const result of results) {
    const existing = grouped.get(result.index) || [];
    existing.push(result);
    grouped.set(result.index, existing);
  }

  return grouped;
}
