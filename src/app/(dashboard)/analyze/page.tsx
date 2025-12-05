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
import { FileUpload } from '@/components/FileUpload';
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

interface FieldExtraction {
  name: string;
  sampleValue: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array' | 'null';
  nested?: boolean;
  path?: string;
}

// Platform/OS types for log files
type LogPlatform =
  | 'windows'
  | 'linux'
  | 'unix'
  | 'macos'
  | 'aws'
  | 'azure'
  | 'gcp'
  | 'docker'
  | 'kubernetes'
  | 'cloud'
  | 'unknown';

// Log format types
type LogFormat =
  | 'json'
  | 'xml'
  | 'csv'
  | 'cef'
  | 'leef'
  | 'windows-evtx'
  | 'syslog'
  | 'apache'
  | 'nginx'
  | 'iis'
  | 'kv'
  | 'custom'
  | 'unknown';

// Input method for Splunk
type SplunkInputMethod =
  | 'monitor'
  | 'hec'
  | 'scripted'
  | 'wmi'
  | 'powershell'
  | 's3'
  | 'kinesis'
  | 'cloudwatch'
  | 'azure-blob'
  | 'gcp-pubsub';

// Input method for Elastic Stack
type ElasticInputMethod =
  | 'filebeat'
  | 'filebeat-aws'
  | 'filebeat-azure'
  | 'filebeat-gcp'
  | 'metricbeat'
  | 'winlogbeat'
  | 'functionbeat'
  | 'logstash'
  | 'elastic-agent';

// Input method for Microsoft Sentinel
type SentinelInputMethod =
  | 'ama'
  | 'log-analytics'
  | 'data-connector'
  | 'syslog'
  | 'cef'
  | 'api'
  | 'logstash'
  | 'function-app';

// Input method for IBM QRadar
type QRadarInputMethod =
  | 'log-source'
  | 'syslog'
  | 'snmp'
  | 'jdbc'
  | 'wincollect'
  | 'api'
  | 'universal-cloud-rest';

// Input method for Cribl Stream
type CriblInputMethod =
  | 'syslog'
  | 'http'
  | 's3'
  | 'kinesis'
  | 'kafka'
  | 'splunk-hec'
  | 'elastic-bulk'
  | 'file-monitor';

interface LogSampleAnalysis {
  timeFormat: string | null;
  timePrefix: string | null;
  lineBreaker: string;
  kvMode: 'auto' | 'json' | 'none';
  maxTimestampLookahead: number;
  detectedFields: string[];
  extractedFields: FieldExtraction[];
  confidence: 'high' | 'medium' | 'low';
  sampleType: 'json' | 'kv' | 'syslog' | 'apache' | 'csv' | 'unknown';
  rawPattern: string | null;
  suggestedPaths: string[];
  detectedVendor: string | null;
  suggestedSourcetype: string | null;
  // New platform/format detection
  detectedPlatform: LogPlatform;
  detectedFormat: LogFormat;
  // SIEM-specific collection methods
  splunkInputMethod: SplunkInputMethod;
  elasticInputMethod: ElasticInputMethod;
  sentinelInputMethod: SentinelInputMethod;
  qradarInputMethod: QRadarInputMethod;
  criblInputMethod: CriblInputMethod;
  inputMethodNotes?: string;
}

export default function AnalyzePage() {
  const [pathsText, setPathsText] = useState('');
  const [selectedSiem, setSelectedSiem] = useState<SIEM>('splunk');
  const [runSensitiveScan, setRunSensitiveScan] = useState(true);
  const [outputFormat, setOutputFormat] = useState<'zip' | 'txt'>('zip');
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [logSample, setLogSample] = useState('');
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

  const handleUseSuggestedPath = (path: string) => {
    setPathsText(path);
  };

  const handleUseAllSuggestedPaths = () => {
    if (sampleAnalysis?.suggestedPaths) {
      setPathsText(sampleAnalysis.suggestedPaths.join('\n'));
    }
  };

  const handleAnalyze = () => {
    analyzeMutation.mutate({
      pathsText,
      siem: selectedSiem,
      runSensitiveScan,
      includeDomainsInConfigs: false,
      outputFormat,
      sampleAnalysis: sampleAnalysis ?? undefined,
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

      {/* Log Sample Analysis - Top Section */}
      <Card className="mb-6">
        <CardHeader>
          <div className="flex items-center gap-2">
            <svg
              className="w-5 h-5 text-green-600"
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
            <CardTitle>Log Sample Analysis</CardTitle>
            <Badge variant="outline" className="text-xs">
              Optional
            </Badge>
          </div>
          <CardDescription>
            Paste a sample log or upload a log file to auto-detect vendor, TIME_FORMAT, and field
            extractions
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Tabs defaultValue="paste" className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="paste">Paste Text</TabsTrigger>
              <TabsTrigger value="upload">Upload File</TabsTrigger>
            </TabsList>
            <TabsContent value="paste" className="space-y-3">
              <Textarea
                placeholder={`Example: 2024-01-15T10:30:45.123Z INFO [main] Application started successfully user=admin action=login`}
                value={logSample}
                onChange={(e) => setLogSample(e.target.value)}
                className="min-h-[100px] font-mono text-xs"
                aria-label="Log sample input for analysis"
              />
            </TabsContent>
            <TabsContent value="upload" className="space-y-3">
              <FileUpload
                onFileRead={(content, _filename) => {
                  setLogSample(content);
                  // Auto-trigger analysis after file upload
                  setTimeout(() => {
                    if (content.trim()) {
                      sampleMutation.mutate({ sample: content });
                    }
                  }, 100);
                }}
                acceptedTypes={['.log', '.json', '.csv', '.txt']}
                maxSizeMB={10}
              />
            </TabsContent>
          </Tabs>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={handleAnalyzeSample}
              disabled={!logSample.trim() || sampleMutation.isPending}
              className="flex-1"
            >
              {sampleMutation.isPending ? 'Analyzing...' : 'Analyze Sample'}
            </Button>
            {sampleMutation.isPending && (
              <Button
                size="sm"
                variant="destructive"
                onClick={() => sampleMutation.reset()}
                aria-label="Cancel log sample analysis"
              >
                Cancel
              </Button>
            )}
          </div>

          {sampleAnalysis && (
            <div className="p-3 bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 rounded-lg space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
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
                <Badge variant="secondary" className="bg-blue-100 dark:bg-blue-900">
                  📟 {sampleAnalysis.detectedPlatform.toUpperCase()}
                </Badge>
                <Badge variant="secondary" className="bg-purple-100 dark:bg-purple-900">
                  📄 {sampleAnalysis.detectedFormat.toUpperCase()}
                </Badge>
                {(() => {
                  const inputMethod = getSiemInputMethod(selectedSiem, sampleAnalysis);
                  const defaultMethod = getDefaultInputMethod(selectedSiem);
                  if (inputMethod !== defaultMethod) {
                    return (
                      <Badge variant="secondary" className="bg-orange-100 dark:bg-orange-900">
                        ⚡ {inputMethod.toUpperCase()}
                      </Badge>
                    );
                  }
                  return null;
                })()}
              </div>
              {sampleAnalysis.inputMethodNotes && (
                <div className="p-2 bg-yellow-50 dark:bg-yellow-950 border border-yellow-200 dark:border-yellow-800 rounded text-xs">
                  <p className="text-yellow-900 dark:text-yellow-200">
                    {sampleAnalysis.inputMethodNotes}
                  </p>
                </div>
              )}
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
                    Detected: <code className="bg-muted px-1">{sampleAnalysis.rawPattern}</code>
                  </div>
                )}
              </div>

              {/* Detected Vendor and Suggested Paths */}
              {sampleAnalysis.detectedVendor && (
                <div className="pt-2 border-t border-green-300 dark:border-green-700">
                  <div className="flex items-center gap-2 mb-2">
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
                        d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <span className="text-sm font-medium text-green-800 dark:text-green-200">
                      Detected: {sampleAnalysis.detectedVendor}
                    </span>
                  </div>
                </div>
              )}

              {sampleAnalysis.suggestedPaths && sampleAnalysis.suggestedPaths.length > 0 && (
                <div className="pt-2">
                  <p className="text-xs font-medium text-green-800 dark:text-green-200 mb-2">
                    Suggested log paths:
                  </p>
                  <div className="space-y-1">
                    {sampleAnalysis.suggestedPaths.map((path, idx) => (
                      <button
                        key={idx}
                        onClick={() => handleUseSuggestedPath(path)}
                        className="w-full text-left px-2 py-1 text-xs font-mono bg-green-100 dark:bg-green-900 hover:bg-green-200 dark:hover:bg-green-800 rounded border border-green-300 dark:border-green-700 transition-colors"
                        aria-label={`Use suggested log path: ${path}`}
                      >
                        {path}
                      </button>
                    ))}
                  </div>
                  <Button
                    size="sm"
                    variant="default"
                    onClick={handleUseAllSuggestedPaths}
                    className="mt-2 w-full"
                  >
                    Use All Suggested Paths
                  </Button>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

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
              aria-label="Log file paths input (one per line)"
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

            <div className="flex gap-2">
              <Button
                onClick={handleAnalyze}
                disabled={!pathsText.trim() || analyzeMutation.isPending}
                className="flex-1"
              >
                {analyzeMutation.isPending ? 'Analyzing...' : 'Analyze Paths'}
              </Button>
              {analyzeMutation.isPending && (
                <Button
                  variant="destructive"
                  onClick={() => analyzeMutation.reset()}
                  aria-label="Cancel path analysis"
                >
                  Cancel
                </Button>
              )}
              <Button
                variant="outline"
                onClick={handleClear}
                disabled={(!pathsText.trim() && !result) || analyzeMutation.isPending}
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
                <div className="overflow-x-auto pb-2">
                  <TabsList className="inline-flex w-auto min-w-full justify-start">
                    <TabsTrigger value="paths" className="flex-shrink-0">
                      Paths
                    </TabsTrigger>
                    <TabsTrigger value="config1" className="flex-shrink-0">
                      {getConfigLabel(selectedSiem, 1)}
                    </TabsTrigger>
                    <TabsTrigger value="config2" className="flex-shrink-0">
                      {getConfigLabel(selectedSiem, 2)}
                    </TabsTrigger>
                    <TabsTrigger value="config3" className="flex-shrink-0">
                      {getConfigLabel(selectedSiem, 3)}
                    </TabsTrigger>
                    {sampleAnalysis && sampleAnalysis.extractedFields.length > 0 && (
                      <TabsTrigger value="fields" className="flex-shrink-0">
                        Fields
                        <Badge variant="outline" className="ml-2 text-xs">
                          {sampleAnalysis.extractedFields.length}
                        </Badge>
                      </TabsTrigger>
                    )}
                    <TabsTrigger value="sensitive" className="flex-shrink-0">
                      Sensitive
                    </TabsTrigger>
                  </TabsList>
                </div>

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

                {sampleAnalysis && sampleAnalysis.extractedFields.length > 0 && (
                  <TabsContent value="fields" className="mt-4">
                    <ExtractedFieldsTable
                      fields={sampleAnalysis.extractedFields}
                      sampleType={sampleAnalysis.sampleType}
                    />
                  </TabsContent>
                )}

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
              aria-label="Show deployment information"
              aria-expanded={showTooltip}
            >
              ?
            </button>
            {showTooltip && (
              <div
                className="absolute z-50 left-6 top-0 w-64 p-3 bg-white dark:bg-zinc-800 border rounded-lg shadow-lg text-xs text-zinc-700 dark:text-zinc-300"
                role="tooltip"
              >
                {info.description}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ExtractedFieldsTable({
  fields,
  sampleType,
}: {
  fields: FieldExtraction[];
  sampleType: string;
}) {
  if (fields.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No fields extracted from log sample
      </div>
    );
  }

  // Group fields by nested status for better organization
  const topLevelFields = fields.filter((f) => !f.nested);
  const nestedFields = fields.filter((f) => f.nested);

  const getTypeColor = (type: string) => {
    const colors: Record<string, string> = {
      string: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      number: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      boolean: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
      object: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
      array: 'bg-pink-100 text-pink-800 dark:bg-pink-900 dark:text-pink-200',
      null: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200',
    };
    return colors[type] || colors.string;
  };

  const truncateValue = (value: string, maxLength = 100) => {
    if (value.length <= maxLength) return value;
    return value.substring(0, maxLength) + '...';
  };

  return (
    <div className="space-y-4">
      {/* Info banner */}
      <div className="p-3 bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-800 rounded-lg">
        <div className="flex items-start gap-2">
          <svg
            className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <div className="flex-1">
            <div className="text-sm font-medium text-blue-900 dark:text-blue-200">
              Extracted {fields.length} field{fields.length !== 1 ? 's' : ''} from {sampleType} log
              sample
            </div>
            <div className="text-xs text-blue-800 dark:text-blue-300 mt-1">
              These fields can be used for field extractions in props.conf or transforms.conf.
              {nestedFields.length > 0 && ` Includes ${nestedFields.length} nested field(s).`}
            </div>
          </div>
        </div>
      </div>

      {/* Top-level fields */}
      {topLevelFields.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-foreground">
            Top-Level Fields ({topLevelFields.length})
          </h3>
          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {topLevelFields.map((field, index) => (
              <div key={index} className="p-3 border rounded-lg bg-card hover:bg-muted/50">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2">
                      <code className="font-mono text-sm font-semibold text-foreground">
                        {field.name}
                      </code>
                      <span
                        className={`text-xs px-2 py-0.5 rounded font-medium ${getTypeColor(field.type)}`}
                      >
                        {field.type}
                      </span>
                    </div>
                    <div className="text-sm text-muted-foreground">
                      <span className="font-medium">Sample value: </span>
                      <code className="bg-muted px-2 py-1 rounded text-xs break-all">
                        {truncateValue(field.sampleValue)}
                      </code>
                    </div>
                    {field.path && field.path !== field.name && (
                      <div className="text-xs text-muted-foreground mt-1">
                        Path: <code className="text-xs">{field.path}</code>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Nested fields */}
      {nestedFields.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-foreground">
            Nested Fields ({nestedFields.length})
          </h3>
          <div className="space-y-2 max-h-[300px] overflow-y-auto">
            {nestedFields.map((field, index) => (
              <div
                key={index}
                className="p-3 border rounded-lg bg-card hover:bg-muted/50 border-l-4 border-l-blue-500"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2">
                      <code className="font-mono text-sm font-semibold text-foreground">
                        {field.name}
                      </code>
                      <span
                        className={`text-xs px-2 py-0.5 rounded font-medium ${getTypeColor(field.type)}`}
                      >
                        {field.type}
                      </span>
                    </div>
                    <div className="text-sm text-muted-foreground">
                      <span className="font-medium">Sample value: </span>
                      <code className="bg-muted px-2 py-1 rounded text-xs break-all">
                        {truncateValue(field.sampleValue)}
                      </code>
                    </div>
                    {field.path && (
                      <div className="text-xs text-muted-foreground mt-1">
                        Full path: <code className="text-xs">{field.path}</code>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SensitiveFindingsTable({ findings }: { findings: SensitiveFinding[] }) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">No sensitive patterns detected</div>
    );
  }

  const getSensitivityExplanation = (pattern: string, description: string): string => {
    const explanations: Record<string, string> = {
      domain_name:
        'Domain names in log paths may expose internal network topology, infrastructure details, or customer/tenant information that should be masked in shared environments.',
      email:
        'Email addresses are Personally Identifiable Information (PII) that must be protected under GDPR, CCPA, and other privacy regulations. Logging emails can expose user identities.',
      ipv4_address:
        'IP addresses can be used to identify users or systems and may be considered PII under privacy regulations. Internal IPs expose network architecture.',
      ssn: 'Social Security Numbers are highly sensitive PII requiring strict protection under federal law. Accidental logging of SSNs is a critical security violation.',
      credit_card:
        'Credit card numbers (PCI DSS data) must never be logged in plaintext. Discovery of card numbers in logs indicates a critical compliance violation.',
      api_key:
        'API keys and tokens provide authentication credentials. Exposure in logs creates security vulnerabilities allowing unauthorized access to systems.',
      password:
        'Passwords or secrets in logs create critical security risks. Even hashed passwords should not be logged due to potential replay attacks.',
      phone:
        'Phone numbers are PII under privacy regulations and can be used to identify individuals. Should be masked in compliance environments.',
    };

    return (
      explanations[pattern] ||
      `${description} detected in log paths. This pattern may contain sensitive information that should be reviewed and potentially masked before indexing.`
    );
  };

  return (
    <div className="space-y-3 max-h-[400px] overflow-y-auto">
      {findings.map((finding, index) => (
        <div key={index} className="p-4 border rounded-lg bg-card">
          <div className="flex items-center justify-between mb-3">
            <div>
              <span className="font-medium text-base">{finding.description}</span>
              <div className="text-sm text-muted-foreground mt-1">
                Pattern:{' '}
                <code className="bg-muted px-1 py-0.5 rounded text-xs">{finding.pattern}</code>
              </div>
            </div>
            <RiskBadge level={finding.riskLevel} />
          </div>

          {/* Why it's sensitive */}
          <div className="mb-3 p-3 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded">
            <div className="flex items-start gap-2">
              <svg
                className="w-4 h-4 text-amber-600 mt-0.5 flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
              <div>
                <div className="text-xs font-medium text-amber-900 dark:text-amber-200 mb-1">
                  Why this is sensitive:
                </div>
                <div className="text-xs text-amber-800 dark:text-amber-300">
                  {getSensitivityExplanation(finding.pattern, finding.description)}
                </div>
              </div>
            </div>
          </div>

          <div className="text-sm text-muted-foreground mb-2">
            <strong>{finding.count}</strong> occurrence(s) found
          </div>

          {/* Recommended action */}
          {finding.maskFormat && (
            <div className="mb-3 text-xs">
              <span className="font-medium text-muted-foreground">Recommended masking: </span>
              <code className="bg-muted px-2 py-1 rounded">{finding.maskFormat}</code>
            </div>
          )}

          {finding.locations && finding.locations.length > 0 && (
            <div className="mt-2 space-y-1">
              <div className="text-xs font-medium text-muted-foreground mb-1">Found in paths:</div>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {finding.locations.map((location, idx) => (
                  <div
                    key={idx}
                    className="text-xs font-mono bg-muted/50 px-2 py-1 rounded border border-muted-foreground/20 break-all"
                  >
                    {location}
                  </div>
                ))}
              </div>
            </div>
          )}
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
      label: 'logstash.conf',
      deployTo: 'Logstash Nodes (Optional)',
      description:
        'Deploy to Logstash for advanced processing. Path: /etc/logstash/conf.d/. Can be skipped if using direct Filebeat → Elasticsearch.',
    },
    {
      label: 'ingest-pipeline.json',
      deployTo: 'Elasticsearch Cluster',
      description:
        'Import via PUT _ingest/pipeline/logonboard API. Handles grok parsing, field extraction, and data masking.',
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
  const siem = result.generatedConfig.siem || 'splunk';
  const configLabels = DEPLOYMENT_GUIDANCE[siem];

  const lines = [
    '='.repeat(80),
    `LogOnboard-AI Configuration Bundle - ${siem.toUpperCase()}`,
    '='.repeat(80),
    '',
    `## ${configLabels[0].label.toUpperCase()}`,
    '-'.repeat(40),
    result.generatedConfig.inputsConf,
    '',
    `## ${configLabels[1].label.toUpperCase()}`,
    '-'.repeat(40),
    result.generatedConfig.propsConf,
    '',
    `## ${configLabels[2].label.toUpperCase()}`,
    '-'.repeat(40),
    result.generatedConfig.transformsConf,
    '',
  ];

  // Add index template for Elastic Stack (4th file)
  if (siem === 'elastic' && result.generatedConfig.elastic?.indexTemplate) {
    lines.push('## INDEX-TEMPLATE.JSON');
    lines.push('-'.repeat(40));
    lines.push(result.generatedConfig.elastic.indexTemplate);
    lines.push('');
  }

  lines.push('## README');
  lines.push('-'.repeat(40));
  lines.push(result.generatedConfig.readme);

  return lines.join('\n');
}

// Helper function to get SIEM-specific input method
function getSiemInputMethod(siem: SIEM, analysis: LogSampleAnalysis): string {
  switch (siem) {
    case 'splunk':
      return analysis.splunkInputMethod;
    case 'elastic':
      return analysis.elasticInputMethod;
    case 'sentinel':
      return analysis.sentinelInputMethod;
    case 'qradar':
      return analysis.qradarInputMethod;
    case 'cribl':
      return analysis.criblInputMethod;
    default:
      return analysis.splunkInputMethod;
  }
}

// Helper function to get default input method for each SIEM
function getDefaultInputMethod(siem: SIEM): string {
  const defaults: Record<SIEM, string> = {
    splunk: 'monitor',
    elastic: 'filebeat',
    sentinel: 'ama',
    qradar: 'log-source',
    cribl: 'file-monitor',
  };
  return defaults[siem];
}
