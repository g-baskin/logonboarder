# LogOnboard-AI Product Roadmap

**Mission:** The open-source, multi-SIEM alternative to Cribl Copilot for intelligent log configuration generation

**Positioning:** For security engineers and SOC analysts who need to onboard logs to multiple SIEM platforms without vendor lock-in or expensive commercial tools.

---

## 🎯 Strategic Priorities

### **Core Differentiators (What Cribl Copilot Can't Do)**

1. ✅ Multi-SIEM support (Splunk, Elastic, Sentinel, QRadar, Cribl)
2. ✅ Open-source and free
3. ✅ Splunk TA → Cribl pipeline translation
4. ✅ Platform-agnostic (works with any SIEM)

---

## 📅 Phase 1: Foundation (Weeks 1-6)

**Goal:** Solidify core platform detection and multi-SIEM support

### **Priority 1: Multi-SIEM Configuration Generation** ⭐⭐⭐⭐⭐

**Status:** In Progress (Splunk complete)

**Deliverables:**

- [x] Splunk (inputs.conf, props.conf, transforms.conf) ✅ DONE
- [ ] **Elastic Stack** (filebeat.yml, logstash.conf, index templates)
  - Generate Filebeat input configurations
  - Generate Logstash pipeline configs
  - Generate index patterns and field mappings
  - Ingest pipeline configurations
- [ ] **Cribl Stream** (pipelines, routes, packs)
  - Generate Cribl pipeline configs
  - Route configurations
  - Pack templates
  - **UNIQUE VALUE**: Splunk TA → Cribl pipeline translation tool
- [ ] **Microsoft Sentinel** (Data Connector ARM templates, DCR configs)
  - Data Collection Rule (DCR) generation
  - ARM template for connectors
  - Kusto Query Language (KQL) parsing rules
- [ ] **IBM QRadar** (DSM configurations, log source configs)
  - Device Support Module (DSM) configs
  - Log source type definitions
  - Custom property extraction rules

**Why This Matters:**

- Cribl Copilot only does Cribl
- No other tool generates configs for all platforms
- **Key differentiator from competition**

**Success Metrics:**

- Generate valid configs for 5 SIEM platforms
- Config validation tests pass
- User can download configs for multiple platforms simultaneously

---

### **Priority 2: File Upload & Advanced Log Analysis** ⭐⭐⭐⭐⭐

**Status:** Not Started

**Deliverables:**

- [ ] Drag-and-drop file upload (.log, .json, .csv, .txt, .evtx)
- [ ] Multi-file analysis (upload multiple log files)
- [ ] Compressed file support (.zip, .tar.gz, .gzip)
- [ ] Multi-line event detection (stack traces, Java logs, XML)
- [ ] Volume estimation (events/sec, MB/day, index sizing)
- [ ] Field extraction preview table
- [ ] Interactive field mapping (rename, exclude, retype fields)

**Why This Matters:**

- Current paste-only UX is limiting
- Analysts have log files, not just samples
- Competitive with Cribl's ease of use

**Success Metrics:**

- 90% of users upload files instead of pasting
- Accurately detect multi-line events
- Provide sizing recommendations within 10% accuracy

---

### **Priority 3: Splunk TA → Cribl Pipeline Translator** ⭐⭐⭐⭐⭐

**Status:** Not Started

**Deliverables:**

- [ ] Upload Splunk TA (Technical Add-on) config files
- [ ] Parse inputs.conf, props.conf, transforms.conf
- [ ] Generate equivalent Cribl Stream pipelines
- [ ] Field extraction translation (Splunk regex → Cribl eval)
- [ ] Data routing translation (transforms → routes)
- [ ] Side-by-side comparison view
- [ ] Migration guide generator

**Why This Matters:**

- **UNIQUE USE CASE** - no one else does this
- Your specific pain point (Splunk TA → Cribl is hard)
- Direct value for orgs moving to Cribl
- Competitive moat against Cribl Copilot

**Success Metrics:**

- 80% accuracy in field extraction translation
- Generate functional Cribl pipelines
- User can migrate 1 TA in <10 minutes

---

### **Priority 4: Configuration Validation & Testing** ⭐⭐⭐⭐

**Status:** Not Started

**Deliverables:**

- [ ] **Syntax Validation**
  - Validate Splunk props.conf regex patterns
  - Check TIME_FORMAT against sample logs
  - Detect common misconfigurations
  - ESLint-style error highlighting
- [ ] **Test Mode / Preview**
  - Simulate event parsing with sample data
  - Show extracted fields (\_time, sourcetype, source, host)
  - Preview how data will appear in SIEM
  - Performance impact estimates
- [ ] **Deployment Checklist Generator** (Multi-SIEM)
  - Splunk: "Deploy inputs.conf to UF, props.conf to HF/Indexer"
  - Elastic: "Deploy filebeat.yml to endpoints, logstash.conf to aggregators"
  - Sentinel: "Deploy ARM template, configure DCR"
  - QRadar: "Upload DSM, configure log source"
  - Cribl: "Deploy pipeline to Cribl workers"
  - Architecture diagram generator
- [ ] **Export Deployment Package**
  - README with step-by-step instructions
  - Config files organized by deployment location
  - Validation scripts
  - Rollback procedures

**Why This Matters:**

- Reduces config errors in production
- Builds trust in generated configs
- Deployment complexity is a major pain point

**Success Metrics:**

- Catch 95% of common config errors
- Zero invalid configs deployed to production
- 80% of users use test mode before deployment

---

## 📅 Phase 2: Differentiation (Months 2-3)

### **Priority 5: Detection Rules & Security Use Cases** ⭐⭐⭐⭐

**Status:** Not Started

**Deliverables:**

- [ ] MITRE ATT&CK technique mapping
- [ ] Auto-suggest detection rules based on log type
- [ ] Generate platform-specific rules:
  - Splunk SPL searches
  - Sigma rules (universal)
  - Elastic Detection Rules (KQL)
  - Sentinel Analytics Rules (KQL)
  - QRadar AQL rules
- [ ] Use case templates library
  - "AWS CloudTrail: 10 Critical Detections"
  - "Windows Event Logs: Lateral Movement Detection"
  - "Failed Authentication Monitoring"
- [ ] SOC Prime / Sigma rule integration

**Why This Matters:**

- Security teams need detections, not just ingestion
- Adds value beyond config generation
- Aligns with MITRE ATT&CK (industry standard)

**Success Metrics:**

- 50+ use case templates
- Generate 10+ detection rules per log type
- Rules compatible with Sigma format

---

### **Priority 6: Interactive Configuration Wizard** ⭐⭐⭐⭐

**Status:** Not Started

**Deliverables:**

- [ ] Step 1: SIEM Selection (multi-select)
- [ ] Step 2: Log Upload or Paste Paths
- [ ] Step 3: Platform/Format Review & Confirmation
- [ ] Step 4: Sourcetype/Index Customization
- [ ] Step 5: Detection Rules (optional)
- [ ] Step 6: Download Configs + Deployment Guide
- [ ] Progress indicator
- [ ] Save/resume wizard state

**Why This Matters:**

- Reduces cognitive load
- Increases completion rate
- Better UX than current all-at-once approach

**Success Metrics:**

- 90% wizard completion rate
- 50% reduction in time-to-config
- 80% user satisfaction score

---

### **Priority 7: Knowledge Base Expansion** ⭐⭐⭐⭐

**Status:** In Progress (15 templates)

**Deliverables:**

- [ ] Expand to 100+ sourcetype templates
- [ ] **Cloud Platforms**
  - AWS: CloudWatch, S3, CloudTrail, VPC Flow, GuardDuty, WAF, ALB/NLB, RDS, Lambda, EKS (20+ services)
  - Azure: Activity Logs, Diagnostic Logs, Sign-in Logs, Audit Logs, Key Vault, App Service, AKS (15+ services)
  - GCP: Audit Logs, VPC Flow, Cloud DNS, GKE, Cloud Functions, Pub/Sub (10+ services)
- [ ] **Containers & Orchestration**
  - Docker, Kubernetes, OpenShift, Rancher, ECS, Nomad
- [ ] **Security Appliances**
  - Palo Alto, Cisco ASA, Fortinet, Check Point, F5, CrowdStrike, SentinelOne, Carbon Black
- [ ] **Web Servers & Apps**
  - Apache, Nginx, IIS, Tomcat, JBoss, WebLogic, HAProxy, Varnish
- [ ] **Databases**
  - MySQL, PostgreSQL, MongoDB, Oracle, MSSQL, Redis, Cassandra, DynamoDB
- [ ] **Operating Systems**
  - Windows Event Logs (Security, System, Application, PowerShell, Sysmon)
  - Linux auditd, auth.log, secure, messages
  - macOS Unified Logs
- [ ] Community contribution system
- [ ] Template validation & testing

**Why This Matters:**

- More templates = more use cases covered
- Reduces "not found" scenarios
- Network effect: users contribute templates

**Success Metrics:**

- 100+ validated templates
- 95% coverage of common log sources
- 10+ community contributions per month

---

## 📅 Phase 3: Scale & Community (Months 4-6)

### **Priority 8: AI Chat Assistant** ⭐⭐⭐

**Status:** Not Started

**Deliverables:**

- [ ] RAG (Retrieval-Augmented Generation) over knowledge base
- [ ] Chat interface: "Ask questions about your logs"
- [ ] Example queries:
  - "How should I configure CloudWatch logs in Splunk?"
  - "What's the difference between HEC and file monitoring?"
  - "Generate a detection rule for failed login attempts"
  - "Translate this Splunk regex to Cribl eval expression"
- [ ] Multi-turn conversations
- [ ] Code generation (configs, SPL, KQL, pipelines)
- [ ] Context-aware suggestions

**User Access:**

- ✅ **All users** (not just you)
- Free tier: 10 questions/day
- Paid tier: Unlimited questions

**Why This Matters:**

- Lowers barrier to entry for junior analysts
- Conversational UX is sticky
- AI assistant is table stakes in 2025

**Success Metrics:**

- 60% of users interact with AI assistant
- 80% helpful rating
- Average 3+ questions per session

---

### **Priority 9: API & CLI Integration** ⭐⭐⭐

**Status:** Not Started

**Deliverables:**

- [ ] REST API
  - POST /api/analyze → configs
  - GET /api/templates → list templates
  - Authentication (API keys)
  - Rate limiting
- [ ] CLI Tool
  ```bash
  logonboard analyze --sample ./app.log --siem splunk,elastic
  logonboard translate --ta ./splunk-ta --output cribl
  ```
- [ ] CI/CD Integration
  - GitHub Actions workflow
  - GitLab CI template
  - Jenkins plugin
- [ ] Terraform Provider
- [ ] Ansible Module

**Why This Matters:**

- Automation-first workflows
- Infrastructure as Code (IaC) integration
- Enterprise adoption driver

**Success Metrics:**

- 30% of configs generated via API
- 10+ CI/CD integrations published
- 1000+ CLI downloads

---

### **Priority 10: Community & Marketplace** ⭐⭐

**Status:** Not Started

**Deliverables:**

- [ ] Community template repository
- [ ] Upvote/downvote quality system
- [ ] User profiles & contributions
- [ ] Template versioning
- [ ] GitHub integration (export to repo)
- [ ] Template search & discovery
- [ ] Certification program (verified templates)

**Why This Matters:**

- Network effects
- Crowdsourced knowledge base
- Viral growth potential

**Success Metrics:**

- 500+ community templates
- 100+ active contributors
- 50% of new templates from community

---

## 💰 Phase 4: Monetization (Months 7-12)

### **Priority 11: Freemium Model**

**Free Tier:**

- Single-user
- Generate configs for all SIEMs
- 10 AI chat questions/day
- Community templates
- Basic validation

**Pro Tier ($29/user/month):**

- Team collaboration (shared workspace)
- Unlimited AI chat
- Advanced validation & testing
- Priority support
- Custom templates (private)
- API access (10K calls/month)

**Enterprise Tier ($Custom):**

- SSO / SAML
- On-premise deployment
- SLA guarantees
- Custom integrations
- Audit logs
- White-label option

---

## 🎯 Success Metrics (6-Month Goals)

### **Product Metrics:**

- 5,000 registered users
- 50,000 configs generated
- 100+ templates in knowledge base
- 95% config validation pass rate
- 5 SIEM platforms supported

### **Engagement Metrics:**

- 60% weekly active users
- 3+ configs generated per user
- 80% NPS (Net Promoter Score)
- 40% conversion to AI chat usage

### **Business Metrics:**

- 100 paying customers (Pro tier)
- $10K MRR (Monthly Recurring Revenue)
- 30% month-over-month growth
- 5 enterprise pilots

---

## 🚀 Next Steps

1. **Week 1-2:** Start Priority 1 - Add Elastic Stack support
2. **Week 3-4:** Priority 2 - File upload functionality
3. **Week 5-6:** Priority 3 - Splunk TA → Cribl translator (YOUR UNIQUE USE CASE)

---

## 📊 Competitive Landscape

### **Direct Competitors:**

- **Cribl Copilot** - AI pipeline generation (Cribl-only, commercial)
- **Splunk Add Data Wizard** - Manual config generation (Splunk-only)

### **Indirect Competitors:**

- Manual configuration (current status quo)
- Consulting services (expensive, slow)
- Internal automation scripts (not scalable)

### **Our Moat:**

- ✅ Only multi-SIEM generator
- ✅ Only open-source option
- ✅ Only Splunk TA → Cribl translator
- ✅ Only free tier

---

**Last Updated:** December 4, 2025
**Version:** 0.4.0
**Maintained By:** LogOnboard-AI Team
