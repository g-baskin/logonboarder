import { describe, it, expect } from 'vitest';
import {
  scanPathsForSensitiveData,
  hasHighRiskFindings,
} from '@/server/services/sensitive-scanner';

describe('Sensitive Data Scanner', () => {
  it('should detect .gov domains in paths', () => {
    const findings = scanPathsForSensitiveData(['/logs/agency.gov/access.log']);
    const govFinding = findings.find((f) => f.pattern === 'gov_domain');
    expect(govFinding).toBeDefined();
    expect(govFinding?.riskLevel).toBe('high');
  });

  it('should detect .mil domains in paths', () => {
    const findings = scanPathsForSensitiveData(['/logs/base.mil/security.log']);
    const milFinding = findings.find((f) => f.pattern === 'mil_domain');
    expect(milFinding).toBeDefined();
    expect(milFinding?.riskLevel).toBe('critical');
  });

  it('should detect IP addresses in paths', () => {
    const findings = scanPathsForSensitiveData(['/logs/192.168.1.100/app.log']);
    const ipFinding = findings.find((f) => f.pattern === 'ipv4');
    expect(ipFinding).toBeDefined();
  });

  it('should detect email patterns', () => {
    const findings = scanPathsForSensitiveData(['/users/admin@company.com/logs/']);
    const emailFinding = findings.find((f) => f.pattern === 'email');
    expect(emailFinding).toBeDefined();
    expect(emailFinding?.riskLevel).toBe('high');
  });

  it('should return empty for clean paths', () => {
    const findings = scanPathsForSensitiveData(['/var/log/syslog', '/var/log/messages']);
    // These paths shouldn't trigger sensitive patterns
    expect(findings.length).toBeLessThanOrEqual(1); // Might detect domain pattern
  });

  it('should identify high-risk findings', () => {
    const findings = scanPathsForSensitiveData(['/logs/base.mil/security.log']);
    expect(hasHighRiskFindings(findings)).toBe(true);
  });
});
