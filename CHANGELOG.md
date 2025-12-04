# Changelog

All notable changes to LogOnboard-AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-04

### Added

#### Vendor-Agnostic Architecture

- **Pattern-based vendor detection system** - Extensible architecture makes it easy to add new vendors
- **Industry best practices integration** - Based on official SIEM add-on documentation from Splunk, Elastic, and vendor documentation (2025)
- **10+ vendor support** with intelligent log type detection:
  - **Palo Alto Networks**: pan:traffic, pan:threat, pan:system, pan:config, pan:userid, pan:globalprotect
  - **Cisco**: cisco:asa, cisco:firepower, cisco:security (with %ASA-, %FPR-, %FTD- detection)
  - **Fortinet**: fgt_traffic, fgt_utm, fgt_event (underscore format per official add-on)
  - **Check Point**: cp_log (underscore format)
  - **AWS**: aws:cloudtrail, aws:cloudwatch:vpcflow (nested sourcetype support)
  - **Microsoft Azure**: azure:monitor:activity, azure:monitor:diagnostics, azure:aad:signin
  - **Apache**: apache:access, apache:error (modern colon format)
  - **Nginx**: nginx:plus:access, nginx:plus:error
  - **Microsoft Windows**: WinEventLog:Security, WinEventLog:System, WinEventLog:Application
  - **Linux Syslog**: linux:syslog (structure-based detection)

#### Modern Sourcetype Naming Conventions

- **2025 standard format**: `vendor:product:component` (colon-separated hierarchy)
- **Legacy format support**: Underscore format for vendors that require it (Fortinet, Check Point)
- **Automatic format selection** via `useUnderscoreFormat` flag per vendor

#### Enhanced Detection Logic

- **Log type-specific detection** for Palo Alto (detects `,traffic,`, `,threat,`, etc. in CSV fields)
- **HTTP method detection** for web servers (Apache/Nginx)
- **Event type detection** for cloud providers (AWS CloudTrail vs VPC Flow Logs)
- **Structured syslog detection** based on format patterns, not just keywords

#### Sample Analysis Improvements

- **Sourcetype override mechanism** - Sample-detected sourcetype takes precedence over path-based detection
- **Vendor confidence scoring** - High confidence when vendor indicators match
- **Generic path suggestions** - Dynamic path generation based on vendor and log type

### Changed

- **Breaking**: Sourcetype format modernization - Old underscore formats (e.g., `access_combined`) migrated to colon format (e.g., `apache:access`)
- **Improved path suggestions** - Now generates vendor-specific paths like `/var/log/pan/traffic.log` instead of hardcoded paths
- **Enhanced error handling** - Better validation of sample analysis results

### Fixed

- **Palo Alto sourcetype mismatch** - Traffic logs now correctly assigned `pan:traffic` instead of generic or wrong sourcetypes
- **Multi-log-type detection bug** - System now suggests only matching log type paths (e.g., traffic sample → only traffic paths, not threat paths)
- **Path-based sourcetype conflicts** - Sample-based detection now properly overrides path-based heuristics

### Documentation

- Added inline documentation references for each vendor (links to official SIEM add-on docs)
- Comprehensive code comments explaining detection logic and best practices
- README updates with vendor-agnostic architecture details

### Technical Details

**Files Modified:**

- `src/server/services/log-sample-analyzer.ts` - Core vendor detection with pattern-based system
- `src/server/api/routers/analyze.ts` - API router with sourcetype override logic
- `src/server/services/generators/index.ts` - Config generator orchestration
- `src/server/services/splunk-generator.ts` - Splunk config generation with sample analysis
- `src/types/logonboard.ts` - TypeScript interface updates for vendor detection
- `src/app/(dashboard)/analyze/page.tsx` - Frontend UI for vendor detection results

**Architecture Improvements:**

- Modular vendor pattern definition using TypeScript interfaces
- Separation of concerns: detection logic separate from config generation
- Type-safe vendor pattern definitions with Zod validation

---

## [0.1.0] - 2024

### Added

- Initial release of LogOnboard-AI
- Multi-SIEM configuration generator (Splunk, Elastic, Sentinel, QRadar, Cribl)
- Log sample analysis with TIME_FORMAT detection
- Sensitive data scanning and masking
- Path-based sourcetype detection
- Copy-to-clipboard functionality
- Dark mode support

---

[0.2.0]: https://github.com/g-baskin/logonboarder/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/g-baskin/logonboarder/releases/tag/v0.1.0
