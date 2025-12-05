# LogOnboard-AI

**Intelligent SIEM configuration generator powered by AI-driven log analysis**

LogOnboard-AI automates the tedious process of onboarding log sources into SIEM platforms like Splunk, Elastic, Sentinel, QRadar, and Cribl. Simply paste your log paths and optional log samples, and get production-ready configuration files in seconds.

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](https://github.com/g-baskin/logonboarder)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16.0-black)](https://nextjs.org/)

---

## ✨ Features

### 🤖 Intelligent Log Analysis

- **Automatic field extraction** - Identifies field names, types, and sample values from any log format
- **Vendor detection** - Recognizes 10+ log sources (Palo Alto, Cisco, AWS, Azure, Apache, etc.)
- **Timestamp parsing** - Detects TIME_FORMAT, TIME_PREFIX, and MAX_TIMESTAMP_LOOKAHEAD
- **Multi-format support** - JSON (nested), key-value, Apache, syslog, CSV, and more

### 🎯 Multi-SIEM Support

Generate configs for:

- **Splunk** - inputs.conf, props.conf, transforms.conf
- **Elastic** - Filebeat YAML, Ingest Pipelines, Index Templates
- **Microsoft Sentinel** - Data Collection Rules, Analytics Rules, Workbooks
- **IBM QRadar** - Log Source Extensions, DSM configs
- **Cribl** - Routes, Pipelines, Packs

### 🔒 Security & Compliance

- **Sensitive data scanning** - Detects PII, credentials, credit cards, SSNs
- **Automatic masking** - Generates transforms.conf with regex-based data redaction
- **Risk assessment** - Categorizes findings by severity (critical, high, medium, low)
- **Compliance-ready** - GDPR, CCPA, PCI-DSS considerations built-in

### 🚀 Modern Architecture

- **Vendor-agnostic** - Pattern-based detection system easy to extend
- **Type-safe** - Full TypeScript with tRPC and Zod validation
- **Real-time** - Instant analysis and config generation
- **Dark mode** - Beautiful UI with light/dark theme support

---

## 🎥 Demo

![LogOnboard-AI Demo](https://via.placeholder.com/800x450?text=LogOnboard-AI+Demo)

> **Try it out:** Paste log paths, analyze a sample log, and download production-ready configs in under 30 seconds.

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 20+ (LTS recommended)
- **PostgreSQL** 14+ (for Prisma ORM)
- **npm** or **pnpm**

### Installation

```bash
# Clone the repository
git clone https://github.com/g-baskin/logonboarder.git
cd logonboarder

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your database credentials

# Run database migrations
npm run db:push

# Start development server
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) to see the app.

---

## 📖 Usage

### Basic Workflow

1. **Enter Log Paths** (one per line)

   ```
   /var/log/pan/traffic.log
   /var/log/apache/access.log
   /var/log/syslog
   ```

2. **Analyze Log Sample** (optional but recommended)
   - Paste a sample log line to auto-detect vendor, timestamp format, and fields
   - See extracted fields with types and sample values
   - Get confidence scoring and vendor identification

3. **Select SIEM Platform**
   - Choose your target: Splunk, Elastic, Sentinel, QRadar, or Cribl

4. **Configure Options**
   - Enable/disable sensitive data scanning
   - Choose output format (ZIP or TXT)

5. **Generate & Download**
   - Get production-ready config files
   - Review deployment instructions
   - Copy-paste into your SIEM

### Example: Splunk Configuration

**Input:**

```
Paths: /var/log/pan/traffic.log
Sample: 2024-01-15T10:30:45Z,10.0.0.1,192.168.1.100,traffic,allow,...
```

**Output:**

```ini
# inputs.conf
[monitor:///var/log/pan/traffic.log]
sourcetype = pan:traffic
index = firewall
disabled = 0

# props.conf
[pan:traffic]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
KV_MODE = none
TRUNCATE = 999999
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend (Next.js 16)                 │
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  Analyze Page  │  │  tRPC Client    │  │  UI Components│ │
│  └────────────────┘  └─────────────────┘  └──────────────┘ │
└────────────────────────────┬────────────────────────────────┘
                             │ Type-safe API
┌────────────────────────────┴────────────────────────────────┐
│                    Backend (tRPC + Zod)                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Routers: analyze, preview, export                  │   │
│  └────────────────────┬────────────────────────────────┘   │
│                       │                                      │
│  ┌────────────────────┴────────────────────────────────┐   │
│  │           Services Layer                             │   │
│  │  • log-sample-analyzer  • path-analyzer             │   │
│  │  • sensitive-scanner    • generators (multi-SIEM)   │   │
│  │  • knowledge-base       • exporter                   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Key Technologies

- **Frontend:** Next.js 16 (App Router), React 19, TailwindCSS 4, Radix UI
- **Backend:** tRPC 11, Zod validation, Prisma ORM
- **Database:** PostgreSQL (via Prisma)
- **Dev Tools:** TypeScript 5, ESLint 9, Prettier, Husky, Vitest

---

## 🧪 Development

### Available Scripts

```bash
# Development
npm run dev              # Start dev server with Turbopack
npm run build            # Production build
npm run start            # Start production server

# Quality
npm run lint             # Run ESLint
npm run lint:fix         # Fix ESLint issues
npm run format           # Format with Prettier
npm run typecheck        # TypeScript type checking

# Testing
npm run test             # Run unit tests (watch mode)
npm run test:run         # Run tests once
npm run test:coverage    # Generate coverage report
npm run test:e2e         # Run Playwright E2E tests

# Database
npm run db:generate      # Generate Prisma client
npm run db:push          # Push schema to database
npm run db:migrate       # Create migration
npm run db:studio        # Open Prisma Studio
```

### Project Structure

```
logonboarder/
├── src/
│   ├── app/                    # Next.js App Router pages
│   │   └── (dashboard)/
│   │       └── analyze/        # Main analysis page
│   ├── server/
│   │   ├── api/
│   │   │   └── routers/        # tRPC routers
│   │   └── services/           # Business logic
│   │       ├── generators/     # SIEM config generators
│   │       ├── knowledge-base/ # Pattern libraries
│   │       └── *.ts            # Core services
│   ├── components/             # React components
│   │   └── ui/                 # Reusable UI components
│   ├── types/                  # TypeScript types
│   └── lib/                    # Utilities
├── prisma/                     # Database schema
├── __tests__/                  # Unit tests
├── e2e/                        # E2E tests
└── public/                     # Static assets
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Guidelines

- Write tests for new features
- Follow existing code style (enforced by ESLint/Prettier)
- Update documentation for user-facing changes
- Keep commits atomic and well-described

---

## 📝 Roadmap

### v0.4.0 (Planned)

- [ ] Error boundaries and improved error handling
- [ ] Accessibility improvements (ARIA labels, keyboard navigation)
- [ ] Field extraction export (CSV/JSON)
- [ ] Batch log analysis
- [ ] Config validation

### v0.5.0 (Future)

- [ ] Custom vendor pattern editor
- [ ] Log preview/visualization
- [ ] API rate limiting
- [ ] Multi-language support
- [ ] Docker deployment

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## 📚 Documentation

- **[API Reference](docs/API.md)** - tRPC endpoints and schemas
- **[Architecture Guide](docs/ARCHITECTURE.md)** - System design deep-dive
- **[Vendor Detection](docs/VENDORS.md)** - Supported log sources
- **[SIEM Generators](docs/GENERATORS.md)** - Config generation logic

---

## 🐛 Known Issues

- **Test Coverage:** Currently at 55%. Working to improve to 80%+
- **E2E Tests:** Limited to home page. Need full workflow coverage
- **Accessibility:** ARIA attributes need expansion

See [GitHub Issues](https://github.com/g-baskin/logonboarder/issues) for more.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Splunk** - For comprehensive SIEM documentation
- **Elastic** - For ECS and Filebeat best practices
- **Vercel** - For Next.js framework and hosting
- **Anthropic** - For Claude AI assistance in development

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/g-baskin/logonboarder/issues)
- **Discussions:** [GitHub Discussions](https://github.com/g-baskin/logonboarder/discussions)
- **Email:** support@logonboard.ai

---

**Built with ❤️ by security engineers, for security engineers.**
