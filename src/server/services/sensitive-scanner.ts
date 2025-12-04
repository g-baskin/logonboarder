import type { SensitiveFinding, RiskLevel } from '@/types/logonboard';
import { getSensitivePatterns } from './knowledge-base';

// Sensitive Data Scanner - Detects PII and sensitive patterns in paths

export function scanPathsForSensitiveData(paths: string[]): SensitiveFinding[] {
  const patterns = getSensitivePatterns();
  const findings: Map<string, SensitiveFinding> = new Map();

  for (const path of paths) {
    for (const [patternName, patternConfig] of Object.entries(patterns)) {
      try {
        const regex = new RegExp(patternConfig.regex, 'gi');
        const matches = path.match(regex);

        if (matches && matches.length > 0) {
          const existingFinding = findings.get(patternName);

          if (existingFinding) {
            existingFinding.count += matches.length;
            if (!existingFinding.locations.includes(path)) {
              existingFinding.locations.push(path);
            }
          } else {
            findings.set(patternName, {
              pattern: patternName,
              description: patternConfig.description,
              riskLevel: patternConfig.risk_level as RiskLevel,
              count: matches.length,
              locations: [path],
              maskFormat: patternConfig.mask_format,
            });
          }
        }
      } catch {
        // Invalid regex, skip
        console.warn(`Invalid regex pattern for ${patternName}`);
      }
    }
  }

  // Sort by risk level (critical first)
  const riskOrder: Record<RiskLevel, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  return Array.from(findings.values()).sort(
    (a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]
  );
}

export function hasHighRiskFindings(findings: SensitiveFinding[]): boolean {
  return findings.some((f) => f.riskLevel === 'critical' || f.riskLevel === 'high');
}

export function getTransformsForMasking(findings: SensitiveFinding[]): string[] {
  const transforms: string[] = [];
  const patterns = getSensitivePatterns();

  for (const finding of findings) {
    if (finding.riskLevel === 'critical' || finding.riskLevel === 'high') {
      const pattern = patterns[finding.pattern];
      if (pattern) {
        transforms.push(
          `[mask_${finding.pattern}]`,
          `REGEX = ${pattern.regex}`,
          `FORMAT = ${pattern.mask_format}`,
          `DEST_KEY = _raw`,
          ''
        );
      }
    }
  }

  return transforms;
}

export function generateSensitivityReport(findings: SensitiveFinding[]): string {
  if (findings.length === 0) {
    return 'No sensitive data patterns detected in the provided paths.';
  }

  const lines: string[] = [
    '# Sensitive Data Scan Report',
    '',
    `Total findings: ${findings.length}`,
    '',
    '## Findings by Risk Level',
    '',
  ];

  const byRisk = groupByRiskLevel(findings);

  for (const [level, levelFindings] of byRisk) {
    lines.push(`### ${level.toUpperCase()} (${levelFindings.length})`);
    for (const finding of levelFindings) {
      lines.push(`- **${finding.description}**: ${finding.count} occurrence(s)`);
      lines.push(
        `  - Locations: ${finding.locations.slice(0, 3).join(', ')}${finding.locations.length > 3 ? '...' : ''}`
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}

function groupByRiskLevel(findings: SensitiveFinding[]): Map<RiskLevel, SensitiveFinding[]> {
  const grouped = new Map<RiskLevel, SensitiveFinding[]>();
  const levels: RiskLevel[] = ['critical', 'high', 'medium', 'low'];

  for (const level of levels) {
    const levelFindings = findings.filter((f) => f.riskLevel === level);
    if (levelFindings.length > 0) {
      grouped.set(level, levelFindings);
    }
  }

  return grouped;
}
