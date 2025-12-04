'use client';

import { useState } from 'react';
import { trpc } from '@/trpc/client';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import type {
  AnalyzeResponse,
  PathAnalysisResult,
  SensitiveFinding,
  SIEM,
} from '@/types/logonboard';

const SIEM_OPTIONS: { value: SIEM; label: string; description: string }[] = [
  { value: 'splunk', label: 'Splunk', description: 'inputs.conf, props.conf, transforms.conf' },
  { value: 'elastic', label: 'Elastic', description: 'Filebeat, Ingest Pipelines, ECS' },
  { value: 'sentinel', label: 'Sentinel', description: 'Data Collection Rules, Analytics' },
  { value: 'qradar', label: 'QRadar', description: 'DSM, Log Source Extensions' },
  { value: 'cribl', label: 'Cribl', description: 'Routes, Pipelines, Packs' },
];

interface LogSampleAnalysis {
  timeFormat: string | null;
  timePrefix: string | null;
  lineBreaker: string;
  kvMode: 'auto' | 'json' | 'none';
  maxTimestampLookahead: number;
  detectedFields: string[];
  confidence: 'high' | 'medium' | 'low';
  sampleType: 'json' | 'kv' | 'syslog' | 'apache' | 'csv' | 'unknown';
  rawPattern: string | null;
}

export default function AnalyzePage() {
  const [pathsText, setPathsText] = useState('');
  const [selectedSiem, setSelectedSiem] = useState<SIEM>('splunk');
  const [runSensitiveScan, setRunSensitiveScan] = useState(true);
  const [outputFormat, setOutputFormat] = useState<'zip' | 'txt'>('zip');
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [logSample, setLogSample] = useState('');
  const [showSampleInput, setShowSampleInput] = useState(false);
  const [sampleAnalysis, setSampleAnalysis] = useState<LogSampleAnalysis | null>(null);

  const analyzeMutation = trpc.analyze.analyzeText.useMutation({
    onSuccess: (data) => {
      setResult(data);
    },
  });

  const sampleMutation = trpc.analyze.analyzeLogSample.useMutation({
    onSuccess: (data) => {
      setSampleAnalysis(data);
    },
  });

  const handleAnalyzeSample = () => {
    if (logSample.trim()) {
      sampleMutation.mutate({ sample: logSample });
    }
  };

  const handleAnalyze = () => {
    analyzeMutation.mutate({
      pathsText,
      siem: selectedSiem,
      runSensitiveScan,
      includeDomainsInConfigs: false,
      outputFormat,
    });
  };

  const handleDownload = () => {
    if (!result) return;

    const content = generateDownloadContent(result);
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `logonboard-config-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleClear = () => {
    setPathsText('');
    setResult(null);
    analyzeMutation.reset();
  };

  return (
    <div className="container mx-auto py-8 px-4 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">LogOnboard-AI</h1>
        <p className="text-muted-foreground">
          Generate SIEM configurations from file paths - no log samples required
        </p>
      </div>

      {/* SIEM Selector */}
      <div className="mb-6">
        <Label className="text-sm font-medium mb-3 block">Target SIEM Platform</Label>
        <div className="flex flex-wrap gap-2">
          {SIEM_OPTIONS.map((option) => (
            <Button
              key={option.value}
              variant={selectedSiem === option.value ? 'default' : 'outline'}
              size="sm"
              onClick={() => setSelectedSiem(option.value)}
              className="flex flex-col items-start h-auto py-2 px-3"
            >
              <span className="font-medium">{option.label}</span>
              <span className="text-xs opacity-70">{option.description}</span>
            </Button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <Card>
          <CardHeader>
            <CardTitle>Log Paths</CardTitle>
            <CardDescription>Enter file paths to analyze (one per line)</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              placeholder={`/var/log/apache2/access.log
/var/log/syslog
C:\\Windows\\System32\\winevt\\Logs\\Security.evtx
/var/log/nginx/error.log`}
              value={pathsText}
              onChange={(e) => setPathsText(e.target.value)}
              className="min-h-[200px] font-mono text-sm"
            />

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <Label htmlFor="sensitive-scan" className="flex flex-col gap-1">
                  <span>Sensitive Data Scan</span>
                  <span className="text-xs text-muted-foreground">
                    Detect PII, domains, and sensitive patterns
                  </span>
                </Label>
                <Switch
                  id="sensitive-scan"
                  checked={runSensitiveScan}
                  onCheckedChange={setRunSensitiveScan}
                />
              </div>

              <div className="flex items-center justify-between">
                <Label className="flex flex-col gap-1">
                  <span>Output Format</span>
                  <span className="text-xs text-muted-foreground">Choose download format</span>
                </Label>
                <div className="flex gap-2">
                  <Button
                    variant={outputFormat === 'txt' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setOutputFormat('txt')}
                  >
                    TXT
                  </Button>
                  <Button
                    variant={outputFormat === 'zip' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setOutputFormat('zip')}
                  >
                    ZIP
                  </Button>
                </div>
              </div>
            </div>

            {/* Log Sample Analysis - Collapsible */}
            <div className="border rounded-lg">
              <button
                onClick={() => setShowSampleInput(!showSampleInput)}
                className="w-full flex items-center justify-between p-3 text-sm font-medium hover:bg-muted/50 rounded-lg"
              >
                <div className="flex items-center gap-2">
                  <svg
                    className="w-4 h-4 text-green-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
                    />
                  </svg>
                  <span>Log Sample Analysis</span>
                  <Badge variant="outline" className="text-xs">
                    Optional
                  </Badge>
                </div>
                <svg
                  className={`w-4 h-4 transition-transform ${showSampleInput ? 'rotate-180' : ''}`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M19 9l-7 7-7-7"
                  />
                </svg>
              </button>

              {showSampleInput && (
                <div className="p-3 pt-0 space-y-3">
                  <p className="text-xs text-muted-foreground">
                    Paste a sample log line to auto-detect TIME_FORMAT, LINE_BREAKER, and field
                    extractions
                  </p>
                  <Textarea
                    placeholder={`Example: 2024-01-15T10:30:45.123Z INFO [main] Application started successfully user=admin action=login`}
                    value={logSample}
                    onChange={(e) => setLogSample(e.target.value)}
                    className="min-h-[80px] font-mono text-xs"
                  />
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleAnalyzeSample}
                    disabled={!logSample.trim() || sampleMutation.isPending}
                  >
                    {sampleMutation.isPending ? 'Analyzing...' : 'Analyze Sample'}
                  </Button>

                  {sampleAnalysis && (
                    <div className="p-3 bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 rounded-lg space-y-2">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant={
                            sampleAnalysis.confidence === 'high'
                              ? 'default'
                              : sampleAnalysis.confidence === 'medium'
                                ? 'secondary'
                                : 'destructive'
                          }
                        >
                          {sampleAnalysis.confidence} confidence
                        </Badge>
                        <Badge variant="outline">{sampleAnalysis.sampleType}</Badge>
                      </div>
                      <div className="text-xs space-y-1 font-mono">
                        {sampleAnalysis.timeFormat && (
                          <div>
                            <span className="text-muted-foreground">TIME_FORMAT = </span>
                            <span className="text-green-700 dark:text-green-400">
                              {sampleAnalysis.timeFormat}
                            </span>
                          </div>
                        )}
                        {sampleAnalysis.timePrefix && (
                          <div>
                            <span className="text-muted-foreground">TIME_PREFIX = </span>
                            <span className="text-green-700 dark:text-green-400">
                              {sampleAnalysis.timePrefix}
                            </span>
                          </div>
                        )}
                        <div>
                          <span className="text-muted-foreground">KV_MODE = </span>
                          <span className="text-green-700 dark:text-green-400">
                            {sampleAnalysis.kvMode}
                          </span>
                        </div>
                        {sampleAnalysis.detectedFields.length > 0 && (
                          <div>
                            <span className="text-muted-foreground">Fields: </span>
                            <span className="text-green-700 dark:text-green-400">
                              {sampleAnalysis.detectedFields.slice(0, 8).join(', ')}
                              {sampleAnalysis.detectedFields.length > 8 && '...'}
                            </span>
                          </div>
                        )}
                        {sampleAnalysis.rawPattern && (
                          <div className="pt-1 text-muted-foreground">
                            Detected:{' '}
                            <code className="bg-muted px-1">{sampleAnalysis.rawPattern}</code>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex gap-2">
              <Button
                onClick={handleAnalyze}
                disabled={!pathsText.trim() || analyzeMutation.isPending}
                className="flex-1"
              >
                {analyzeMutation.isPending ? 'Analyzing...' : 'Analyze Paths'}
              </Button>
              <Button
                variant="outline"
                onClick={handleClear}
                disabled={!pathsText.trim() && !result}
              >
                Clear
              </Button>
            </div>

            {analyzeMutation.isError && (
              <p className="text-sm text-red-500">Error: {analyzeMutation.error.message}</p>
            )}
          </CardContent>
        </Card>

        {/* Results Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Analysis Results</span>
              {result && (
                <Button size="sm" onClick={handleDownload}>
                  Download Config
                </Button>
              )}
            </CardTitle>
            <CardDescription>
              {result
                ? `${result.pathAnalysis.length} path(s) analyzed`
                : 'Results will appear here'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {result ? (
              <Tabs defaultValue="paths" className="w-full">
                <TabsList className="grid w-full grid-cols-5">
                  <TabsTrigger value="paths">Paths</TabsTrigger>
                  <TabsTrigger value="config1">{getConfigLabel(selectedSiem, 1)}</TabsTrigger>
                  <TabsTrigger value="config2">{getConfigLabel(selectedSiem, 2)}</TabsTrigger>
                  <TabsTrigger value="config3">{getConfigLabel(selectedSiem, 3)}</TabsTrigger>
                  <TabsTrigger value="sensitive">Sensitive</TabsTrigger>
                </TabsList>

                <TabsContent value="paths" className="mt-4">
                  <PathAnalysisTable results={result.pathAnalysis} />
                </TabsContent>

                <TabsContent value="config1" className="mt-4">
                  <ConfigPreview
                    content={result.generatedConfig.inputsConf}
                    deployInfo={getDeploymentInfo(selectedSiem, 0)}
                  />
                </TabsContent>

                <TabsContent value="config2" className="mt-4">
                  <ConfigPreview
                    content={result.generatedConfig.propsConf}
                    deployInfo={getDeploymentInfo(selectedSiem, 1)}
                  />
                </TabsContent>

                <TabsContent value="config3" className="mt-4">
                  <ConfigPreview
                    content={result.generatedConfig.transformsConf}
                    deployInfo={getDeploymentInfo(selectedSiem, 2)}
                  />
                </TabsContent>

                <TabsContent value="sensitive" className="mt-4">
                  <SensitiveFindingsTable findings={result.sensitiveFindings} />
                </TabsContent>
              </Tabs>
            ) : (
              <div className="text-center py-12 text-muted-foreground">
                Enter paths and click &quot;Analyze Paths&quot; to generate configurations
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function PathAnalysisTable({ results }: { results: PathAnalysisResult[] }) {
  return (
    <div className="space-y-2 max-h-[400px] overflow-y-auto">
      {results.map((result, index) => (
        <div key={index} className="p-3 border rounded-lg text-sm">
          <div className="flex items-start justify-between gap-2">
            <code className="text-xs break-all flex-1">{result.path}</code>
            <ConfidenceBadge confidence={result.confidence} />
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            <Badge variant="outline">{result.sourcetype}</Badge>
            <Badge variant="secondary">index: {result.index}</Badge>
            <Badge variant="secondary">{result.matchType}</Badge>
          </div>
        </div>
      ))}
    </div>
  );
}

function ConfigPreview({ content, deployInfo }: { content: string; deployInfo?: ConfigInfo }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-2">
      {deployInfo && deployInfo.deployTo && <DeploymentBanner info={deployInfo} />}
      <div className="relative">
        <Button
          size="sm"
          variant="outline"
          onClick={handleCopy}
          className="absolute top-2 right-2 z-10 h-8 px-3 text-xs"
        >
          {copied ? (
            <>
              <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 13l4 4L19 7"
                />
              </svg>
              Copied!
            </>
          ) : (
            <>
              <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                />
              </svg>
              Copy
            </>
          )}
        </Button>
        <pre className="p-4 pt-12 bg-muted rounded-lg text-xs overflow-auto max-h-[350px] font-mono select-all">
          {content}
        </pre>
      </div>
    </div>
  );
}

function DeploymentBanner({ info }: { info: ConfigInfo }) {
  const [showTooltip, setShowTooltip] = useState(false);

  return (
    <div className="flex items-center gap-2 p-3 bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 rounded-lg">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <svg
            className="w-4 h-4 text-blue-600"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
            />
          </svg>
          <span className="text-sm font-medium text-blue-800 dark:text-blue-200">
            Deploy to: <span className="font-bold">{info.deployTo}</span>
          </span>
          <div className="relative">
            <button
              onMouseEnter={() => setShowTooltip(true)}
              onMouseLeave={() => setShowTooltip(false)}
              onClick={() => setShowTooltip(!showTooltip)}
              className="w-5 h-5 rounded-full bg-blue-200 dark:bg-blue-800 text-blue-700 dark:text-blue-300 flex items-center justify-center text-xs font-bold hover:bg-blue-300 dark:hover:bg-blue-700"
            >
              ?
            </button>
            {showTooltip && (
              <div className="absolute z-50 left-6 top-0 w-64 p-3 bg-white dark:bg-zinc-800 border rounded-lg shadow-lg text-xs text-zinc-700 dark:text-zinc-300">
                {info.description}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function SensitiveFindingsTable({ findings }: { findings: SensitiveFinding[] }) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">No sensitive patterns detected</div>
    );
  }

  return (
    <div className="space-y-2 max-h-[400px] overflow-y-auto">
      {findings.map((finding, index) => (
        <div key={index} className="p-3 border rounded-lg">
          <div className="flex items-center justify-between">
            <span className="font-medium">{finding.description}</span>
            <RiskBadge level={finding.riskLevel} />
          </div>
          <div className="mt-1 text-sm text-muted-foreground">
            {finding.count} occurrence(s) found
          </div>
        </div>
      ))}
    </div>
  );
}

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const variants: Record<string, 'default' | 'secondary' | 'destructive'> = {
    high: 'default',
    medium: 'secondary',
    low: 'destructive',
  };
  return <Badge variant={variants[confidence] || 'secondary'}>{confidence}</Badge>;
}

function RiskBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-green-500 text-white',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[level] || ''}`}>{level}</span>
  );
}

interface ConfigInfo {
  label: string;
  deployTo: string;
  description: string;
}

// Deployment guidance per SIEM - where each config file should be deployed
const DEPLOYMENT_GUIDANCE: Record<SIEM, [ConfigInfo, ConfigInfo, ConfigInfo]> = {
  splunk: [
    {
      label: 'inputs.conf',
      deployTo: 'Universal Forwarder (UF)',
      description:
        'Deploy to each log source endpoint. Path: $SPLUNK_HOME/etc/apps/<app>/local/inputs.conf',
    },
    {
      label: 'props.conf',
      deployTo: 'Heavy Forwarder (HF) or Indexer',
      description:
        'Deploy to HF for parsing before indexing, or Indexer for index-time extractions. Search Head for search-time only.',
    },
    {
      label: 'transforms.conf',
      deployTo: 'Heavy Forwarder (HF) or Indexer',
      description:
        'Deploy alongside props.conf. Data masking/transformation happens here before data reaches indexers.',
    },
  ],
  elastic: [
    {
      label: 'filebeat.yml',
      deployTo: 'Edge Nodes / Log Sources',
      description: 'Deploy Filebeat agent on each log source. Config at /etc/filebeat/filebeat.yml',
    },
    {
      label: 'ingest-pipeline.json',
      deployTo: 'Elasticsearch Cluster',
      description: 'Import via Kibana Dev Tools or PUT _ingest/pipeline API. Runs on ingest nodes.',
    },
    {
      label: 'index-template.json',
      deployTo: 'Elasticsearch Cluster',
      description: 'Import via PUT _index_template API. Defines mappings for ECS compliance.',
    },
  ],
  sentinel: [
    {
      label: 'DCR.json',
      deployTo: 'Azure Monitor Agent (AMA)',
      description:
        'Data Collection Rules deployed via Azure Portal or ARM template. Associates with AMA on endpoints.',
    },
    {
      label: 'analytics-rules.json',
      deployTo: 'Sentinel Workspace',
      description:
        'Import via Sentinel > Analytics. KQL-based detection rules run in the workspace.',
    },
    {
      label: 'workbook.json',
      deployTo: 'Sentinel Workspace',
      description: 'Import via Sentinel > Workbooks. Visualizations for monitoring ingested data.',
    },
  ],
  qradar: [
    {
      label: 'log-source-extension.xml',
      deployTo: 'QRadar Console',
      description:
        'Import via Admin > DSM Editor > Upload. Defines parsing logic for custom log sources.',
    },
    {
      label: 'dsm-config.txt',
      deployTo: 'QRadar Console',
      description: 'Reference for configuring log sources. Apply via Admin > Log Sources.',
    },
    {
      label: '',
      deployTo: '',
      description: '',
    },
  ],
  cribl: [
    {
      label: 'routes.yml',
      deployTo: 'Cribl Worker Nodes',
      description:
        'Routes deployed via Leader to Worker Groups. Defines data flow from sources to destinations.',
    },
    {
      label: 'pipelines.yml',
      deployTo: 'Cribl Worker Nodes',
      description:
        'Processing pipelines run on Workers. Data transformation/enrichment happens here.',
    },
    {
      label: 'pack.yml',
      deployTo: 'Cribl Leader',
      description: 'Import Pack via Packs > Add Pack. Distributes to Worker Groups automatically.',
    },
  ],
};

function getConfigLabel(siem: SIEM, index: 1 | 2 | 3): string {
  const info = DEPLOYMENT_GUIDANCE[siem][index - 1];
  return info.label || `Config ${index}`;
}

function getDeploymentInfo(siem: SIEM, index: 0 | 1 | 2): ConfigInfo {
  return DEPLOYMENT_GUIDANCE[siem][index];
}

function generateDownloadContent(result: AnalyzeResponse): string {
  const lines = [
    '='.repeat(80),
    'LogOnboard-AI Configuration Bundle',
    '='.repeat(80),
    '',
    '## INPUTS.CONF',
    '-'.repeat(40),
    result.generatedConfig.inputsConf,
    '',
    '## PROPS.CONF',
    '-'.repeat(40),
    result.generatedConfig.propsConf,
    '',
    '## TRANSFORMS.CONF',
    '-'.repeat(40),
    result.generatedConfig.transformsConf,
    '',
    '## README',
    '-'.repeat(40),
    result.generatedConfig.readme,
  ];
  return lines.join('\n');
}
