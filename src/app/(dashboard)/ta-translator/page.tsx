'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { FileUpload } from '@/components/FileUpload';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { ArrowRight, Download, FileCode, AlertTriangle, X, HelpCircle } from 'lucide-react';
import { trpc } from '@/trpc/client';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

interface TAConfig {
  inputsConf?: string;
  propsConf?: string;
  transformsConf?: string;
}

interface TranslationBreakdown {
  splunkConfig: string;
  criblConfig: string;
  configType: 'input' | 'prop' | 'transform';
  criblComponentType: 'route' | 'pipeline' | 'function';
  criblFunctionType?:
    | 'auto_timestamp'
    | 'regex_extract'
    | 'parser'
    | 'eval'
    | 'mask'
    | 'drop'
    | 'grok'
    | 'lookup'
    | 'event_breaker';
  criblFields?: string;
  title: string;
  what: string;
  why: string;
  how: string;
  validation: string;
  autoHandled?: string;
  notTranslated?: string;
}

interface CriblPipeline {
  routes: string;
  pipelines: string;
  functions: string;
  notes: string[];
  warnings: string[];
  breakdown: TranslationBreakdown[];
}

export default function TATranslatorPage() {
  const [taConfig, setTaConfig] = useState<TAConfig>({});
  const [criblOutput, setCriblOutput] = useState<CriblPipeline | null>(null);

  // tRPC mutation for translation
  const translateMutation = trpc.taTranslator.translate.useMutation({
    onSuccess: (data) => {
      setCriblOutput(data);
    },
  });

  const handleFileUpload = (content: string, filename: string) => {
    // Determine which config file based on filename
    const lowerName = filename.toLowerCase();
    if (lowerName.includes('inputs.conf')) {
      setTaConfig((prev) => ({ ...prev, inputsConf: content }));
    } else if (lowerName.includes('props.conf')) {
      setTaConfig((prev) => ({ ...prev, propsConf: content }));
    } else if (lowerName.includes('transforms.conf')) {
      setTaConfig((prev) => ({ ...prev, transformsConf: content }));
    }
  };

  const handleTranslate = () => {
    translateMutation.mutate({
      inputsConf: taConfig.inputsConf,
      propsConf: taConfig.propsConf,
      transformsConf: taConfig.transformsConf,
    });
  };

  const clearInputsConf = () => {
    setTaConfig((prev) => ({ ...prev, inputsConf: undefined }));
  };

  const clearPropsConf = () => {
    setTaConfig((prev) => ({ ...prev, propsConf: undefined }));
  };

  const clearTransformsConf = () => {
    setTaConfig((prev) => ({ ...prev, transformsConf: undefined }));
  };

  const clearAll = () => {
    setTaConfig({});
    setCriblOutput(null);
  };

  const hasAnyConfig = taConfig.inputsConf || taConfig.propsConf || taConfig.transformsConf;
  const isDev = process.env.NODE_ENV === 'development';

  const downloadCriblConfig = () => {
    if (!criblOutput) return;

    const fullConfig = `# Cribl Configuration Package
# Translated from Splunk TA by LogOnboard-AI
# Generated: ${new Date().toISOString()}

# ============================================
# ROUTES
# ============================================
${criblOutput.routes}

# ============================================
# PIPELINES
# ============================================
${criblOutput.pipelines}

# ============================================
# FUNCTIONS
# ============================================
${criblOutput.functions}

# ============================================
# TRANSLATION NOTES
# ============================================
${criblOutput.notes.map((n) => `# ✓ ${n}`).join('\n')}

# ============================================
# WARNINGS
# ============================================
${criblOutput.warnings.map((w) => `# ⚠ ${w}`).join('\n')}
`;

    const blob = new Blob([fullConfig], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cribl-config-${Date.now()}.yml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="container mx-auto py-8 px-4 max-w-6xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold">Splunk TA → Cribl Translator</h1>
            <Badge
              variant="outline"
              className="bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100"
            >
              BETA
            </Badge>
            {isDev && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-8 w-8">
                      <HelpCircle className="h-4 w-4 text-muted-foreground" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-sm">
                    <div className="space-y-2 text-xs">
                      <p className="font-semibold">How Translation Works:</p>
                      <ul className="list-disc list-inside space-y-1">
                        <li>
                          <strong>inputs.conf</strong> → Cribl <strong>routes.yml</strong> (data
                          sources)
                        </li>
                        <li>
                          <strong>props.conf</strong> → Cribl <strong>pipelines.yml</strong>{' '}
                          (parsing rules)
                        </li>
                        <li>
                          <strong>transforms.conf</strong> → Cribl <strong>functions.yml</strong>{' '}
                          (field extractions)
                        </li>
                      </ul>
                      <p className="text-muted-foreground italic pt-2">
                        The translator parses Splunk INI-style configs and generates equivalent
                        Cribl YAML configurations automatically.
                      </p>
                    </div>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
          </div>
          {hasAnyConfig && (
            <Button variant="outline" size="sm" onClick={clearAll}>
              <X className="mr-2 h-4 w-4" />
              Clear All
            </Button>
          )}
        </div>
        <p className="text-muted-foreground">
          Migrate your Splunk Technical Add-ons to Cribl Stream pipelines automatically
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Left: Splunk TA Upload */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5" />
              Splunk Technical Add-on Files
            </CardTitle>
            <CardDescription>Upload your TA configuration files</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* inputs.conf */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium flex items-center gap-2">
                  inputs.conf
                  {taConfig.inputsConf && (
                    <Badge variant="secondary" className="text-xs">
                      ✓ Loaded
                    </Badge>
                  )}
                </Label>
                {taConfig.inputsConf && (
                  <Button variant="ghost" size="sm" onClick={clearInputsConf} className="h-6 px-2">
                    <X className="h-3 w-3" />
                  </Button>
                )}
              </div>
              <FileUpload
                onFileRead={handleFileUpload}
                acceptedTypes={['.conf', '.txt']}
                maxSizeMB={5}
              />
              {taConfig.inputsConf && (
                <Textarea
                  value={taConfig.inputsConf}
                  onChange={(e) => setTaConfig((prev) => ({ ...prev, inputsConf: e.target.value }))}
                  className="font-mono text-xs h-32"
                  placeholder="[monitor://path/to/logs]"
                />
              )}
            </div>

            {/* props.conf */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium flex items-center gap-2">
                  props.conf
                  {taConfig.propsConf && (
                    <Badge variant="secondary" className="text-xs">
                      ✓ Loaded
                    </Badge>
                  )}
                </Label>
                {taConfig.propsConf && (
                  <Button variant="ghost" size="sm" onClick={clearPropsConf} className="h-6 px-2">
                    <X className="h-3 w-3" />
                  </Button>
                )}
              </div>
              <FileUpload
                onFileRead={handleFileUpload}
                acceptedTypes={['.conf', '.txt']}
                maxSizeMB={5}
              />
              {taConfig.propsConf && (
                <Textarea
                  value={taConfig.propsConf}
                  onChange={(e) => setTaConfig((prev) => ({ ...prev, propsConf: e.target.value }))}
                  className="font-mono text-xs h-32"
                  placeholder="[sourcetype]"
                />
              )}
            </div>

            {/* transforms.conf */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium flex items-center gap-2">
                  transforms.conf (optional)
                  {taConfig.transformsConf && (
                    <Badge variant="secondary" className="text-xs">
                      ✓ Loaded
                    </Badge>
                  )}
                </Label>
                {taConfig.transformsConf && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearTransformsConf}
                    className="h-6 px-2"
                  >
                    <X className="h-3 w-3" />
                  </Button>
                )}
              </div>
              <FileUpload
                onFileRead={handleFileUpload}
                acceptedTypes={['.conf', '.txt']}
                maxSizeMB={5}
              />
              {taConfig.transformsConf && (
                <Textarea
                  value={taConfig.transformsConf}
                  onChange={(e) =>
                    setTaConfig((prev) => ({ ...prev, transformsConf: e.target.value }))
                  }
                  className="font-mono text-xs h-32"
                  placeholder="[transform_name]"
                />
              )}
            </div>

            <Button
              onClick={handleTranslate}
              disabled={!hasAnyConfig || translateMutation.isPending}
              className="w-full"
              size="lg"
            >
              {translateMutation.isPending ? (
                'Translating...'
              ) : (
                <>
                  Translate to Cribl <ArrowRight className="ml-2 h-4 w-4" />
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Right: Cribl Output */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5 text-green-600" />
              Cribl Stream Configuration
            </CardTitle>
            <CardDescription>Generated Cribl pipelines and routes</CardDescription>
          </CardHeader>
          <CardContent>
            {!criblOutput ? (
              <div className="text-center py-12 text-muted-foreground">
                <FileCode className="mx-auto h-16 w-16 opacity-20 mb-4" />
                <p>Upload Splunk TA files and click Translate to see Cribl configuration</p>
              </div>
            ) : (
              <div className="space-y-4">
                <Tabs defaultValue="routes">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="routes">Routes</TabsTrigger>
                    <TabsTrigger value="pipelines">Pipelines</TabsTrigger>
                    <TabsTrigger value="functions">Functions</TabsTrigger>
                  </TabsList>
                  <TabsContent value="routes">
                    <Textarea
                      value={criblOutput.routes}
                      readOnly
                      className="font-mono text-xs h-64"
                    />
                  </TabsContent>
                  <TabsContent value="pipelines">
                    <Textarea
                      value={criblOutput.pipelines}
                      readOnly
                      className="font-mono text-xs h-64"
                    />
                  </TabsContent>
                  <TabsContent value="functions">
                    <Textarea
                      value={criblOutput.functions}
                      readOnly
                      className="font-mono text-xs h-64"
                    />
                  </TabsContent>
                </Tabs>

                {/* Translation Notes */}
                <div className="bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 rounded-lg p-3 space-y-1">
                  <p className="text-sm font-medium text-green-900 dark:text-green-100">
                    Translation Notes:
                  </p>
                  {criblOutput.notes.map((note, i) => (
                    <p key={i} className="text-xs text-green-700 dark:text-green-300">
                      ✓ {note}
                    </p>
                  ))}
                </div>

                {/* Warnings */}
                {criblOutput.warnings.length > 0 && (
                  <div className="bg-yellow-50 dark:bg-yellow-950 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3 space-y-1">
                    <p className="text-sm font-medium text-yellow-900 dark:text-yellow-100 flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4" />
                      Warnings:
                    </p>
                    {criblOutput.warnings.map((warning, i) => (
                      <p key={i} className="text-xs text-yellow-700 dark:text-yellow-300">
                        ⚠ {warning}
                      </p>
                    ))}
                  </div>
                )}

                <Button onClick={downloadCriblConfig} variant="outline" className="w-full">
                  <Download className="mr-2 h-4 w-4" />
                  Download Cribl Configuration
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Translation Breakdown Section */}
      {criblOutput && criblOutput.breakdown && criblOutput.breakdown.length > 0 && (
        <div className="mt-8">
          <Card>
            <CardHeader>
              <CardTitle>Translation Breakdown</CardTitle>
              <CardDescription>
                Detailed explanation of each Splunk to Cribl translation
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {criblOutput.breakdown.map((item, idx) => (
                <div
                  key={idx}
                  className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 space-y-4"
                >
                  {/* Title with badges */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-lg font-semibold">{item.title}</h3>
                    <Badge
                      variant="outline"
                      className={
                        item.configType === 'input'
                          ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100'
                          : item.configType === 'prop'
                            ? 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-100'
                            : 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100'
                      }
                    >
                      {item.configType === 'input'
                        ? 'Input'
                        : item.configType === 'prop'
                          ? 'Props'
                          : 'Transform'}
                    </Badge>
                    <Badge
                      variant="outline"
                      className="bg-cyan-100 dark:bg-cyan-900 text-cyan-800 dark:text-cyan-100"
                    >
                      Cribl{' '}
                      {item.criblComponentType.charAt(0).toUpperCase() +
                        item.criblComponentType.slice(1)}
                    </Badge>
                    {item.criblFunctionType && (
                      <Badge
                        variant="outline"
                        className="bg-teal-100 dark:bg-teal-900 text-teal-800 dark:text-teal-100"
                      >
                        {item.criblFunctionType.toUpperCase()} Function
                      </Badge>
                    )}
                  </div>

                  {/* Side-by-side config comparison */}
                  <div className="grid md:grid-cols-2 gap-4">
                    <div>
                      <Label className="text-sm font-medium mb-2 block">Splunk Config</Label>
                      <Textarea
                        value={item.splunkConfig}
                        readOnly
                        className="font-mono text-xs h-32 bg-amber-50 dark:bg-amber-950 border-amber-200 dark:border-amber-800"
                      />
                    </div>
                    <div>
                      <Label className="text-sm font-medium mb-2 block">Cribl Config</Label>
                      <Textarea
                        value={item.criblConfig}
                        readOnly
                        className="font-mono text-xs h-32 bg-green-50 dark:bg-green-950 border-green-200 dark:border-green-800"
                      />
                    </div>
                  </div>

                  {/* Copy-pasteable Cribl Fields */}
                  {item.criblFields && (
                    <div className="bg-cyan-50 dark:bg-cyan-950 border border-cyan-200 dark:border-cyan-800 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-2">
                        <Label className="text-sm font-semibold text-cyan-900 dark:text-cyan-100">
                          Copy-Pasteable Cribl{' '}
                          {item.criblComponentType.charAt(0).toUpperCase() +
                            item.criblComponentType.slice(1)}{' '}
                          Fields
                        </Label>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 text-xs"
                          onClick={() => {
                            navigator.clipboard.writeText(item.criblFields!);
                          }}
                        >
                          Copy
                        </Button>
                      </div>
                      <pre className="font-mono text-xs text-cyan-900 dark:text-cyan-100 whitespace-pre-wrap overflow-x-auto">
                        {item.criblFields}
                      </pre>
                    </div>
                  )}

                  {/* Explanation sections */}
                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <div>
                        <p className="text-sm font-semibold text-blue-700 dark:text-blue-300">
                          What is being done?
                        </p>
                        <p className="text-sm text-gray-700 dark:text-gray-300">{item.what}</p>
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-purple-700 dark:text-purple-300">
                          Why is this done?
                        </p>
                        <p className="text-sm text-gray-700 dark:text-gray-300">{item.why}</p>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <div>
                        <p className="text-sm font-semibold text-orange-700 dark:text-orange-300">
                          How is this done?
                        </p>
                        <p className="text-sm text-gray-700 dark:text-gray-300">{item.how}</p>
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-green-700 dark:text-green-300">
                          Validation & Correctness
                        </p>
                        <pre className="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap font-mono">
                          {item.validation}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Auto-Handled Settings Section */}
                  {item.autoHandled && (
                    <div className="bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 rounded-lg p-4">
                      <p className="text-sm font-semibold text-green-900 dark:text-green-100 mb-2">
                        ✅ Auto-Handled Settings (No Action Required)
                      </p>
                      <p className="text-sm text-green-800 dark:text-green-200 whitespace-pre-wrap">
                        {item.autoHandled}
                      </p>
                    </div>
                  )}

                  {/* Not Translated Section */}
                  {item.notTranslated && (
                    <div className="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-lg p-4">
                      <p className="text-sm font-semibold text-amber-900 dark:text-amber-100 mb-2">
                        ⚠️ Requires Manual Configuration
                      </p>
                      <p className="text-sm text-amber-800 dark:text-amber-200 whitespace-pre-wrap">
                        {item.notTranslated}
                      </p>
                    </div>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
