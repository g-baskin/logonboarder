import { describe, it, expect } from 'vitest';
import { analyzePath, analyzePaths, parsePath } from '@/server/services/path-analyzer';

describe('Path Parser', () => {
  it('should parse Unix paths correctly', () => {
    const result = parsePath('/var/log/apache2/access.log');
    expect(result.filename).toBe('access.log');
    expect(result.directory).toBe('/var/log/apache2');
    expect(result.extension).toBe('.log');
  });

  it('should parse Windows paths correctly', () => {
    const result = parsePath('C:\\Windows\\System32\\winevt\\Logs\\Security.evtx');
    expect(result.filename).toBe('Security.evtx');
    expect(result.extension).toBe('.evtx');
  });
});

describe('Path Analyzer', () => {
  it('should detect Apache access logs', () => {
    const result = analyzePath('/var/log/apache2/access.log');
    expect(result.sourcetype).toBe('access_combined');
    expect(result.index).toBe('web');
    expect(result.confidence).toBe('high');
    expect(result.matchType).toBe('filename');
  });

  it('should detect syslog', () => {
    const result = analyzePath('/var/log/syslog');
    expect(result.sourcetype).toBe('syslog');
    expect(result.index).toBe('os');
    expect(result.confidence).toBe('high');
  });

  it('should detect Windows Security events', () => {
    const result = analyzePath('C:\\Windows\\System32\\winevt\\Logs\\Security.evtx');
    // Matches 'security' filename pattern first
    expect(result.sourcetype).toBe('WinEventLog:Security');
    expect(result.confidence).toBe('high');
    expect(result.matchType).toBe('filename');
  });

  it('should handle unknown paths with fallback', () => {
    // Use a truly unknown filename
    const result = analyzePath('/custom/path/foobar123.xyz');
    expect(result.confidence).toBe('low');
    expect(result.matchType).toBe('fallback');
  });

  it('should analyze multiple paths', () => {
    const results = analyzePaths([
      '/var/log/syslog',
      '/var/log/apache2/access.log',
      '/var/log/nginx/error.log',
    ]);
    expect(results).toHaveLength(3);
    expect(results[0].sourcetype).toBe('syslog');
    expect(results[1].sourcetype).toBe('access_combined');
  });
});
