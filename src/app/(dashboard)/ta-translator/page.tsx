'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { FileUpload } from '@/components/FileUpload';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { ArrowRight, Download, FileCode, AlertTriangle } from 'lucide-react';

interface TAConfig {
  inputsConf?: string;
  propsConf?: string;
  transformsConf?: string;
}

interface CriblPipeline {
  routes: string;
  pipelines: string;
  functions: string;
  notes: string[];
  warnings: string[];
}

export default function TATranslatorPage() {
  const [taConfig, setTaConfig] = useState<TAConfig>({});
  const [criblOutput, setCriblOutput] = useState<CriblPipeline | null>(null);
  const [isTranslating, setIsTranslating] = useState(false);

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

  const handleTranslate = async () => {
    setIsTranslating(true);

    // TODO: Call API to translate Splunk TA → Cribl
    // For now, just show a mock translation after 2 seconds
    setTimeout(() => {
      setCriblOutput({
        routes: `# Cribl Routes Configuration
# Translated from Splunk TA

routes:
  - id: splunk_ta_route
    name: "Splunk TA Data Route"
    filter: "true"
    output: default
    description: "Route for data from translated Splunk TA"
`,
        pipelines: `# Cribl Pipeline Configuration
# Field extractions translated from props.conf/transforms.conf

pipelines:
  - id: splunk_ta_pipeline
    name: "Splunk TA Pipeline"
    functions:
      - id: extract_fields
        filter: "true"
        conf:
          mode: "regex"
          # Field extractions from props.conf REGEX/EXTRACT
`,
        functions: `# Cribl Functions
# Translated from Splunk field extractions

functions:
  - eval:
      - name: "field1"
        value: "C.extract(/regex_pattern/)"
  - parser:
      type: "regex"
      regex: "/your_regex_here/"
`,
        notes: [
          'Successfully translated inputs.conf → Cribl data sources',
          'Converted props.conf TIME_FORMAT → Cribl timestamp extraction',
          'Mapped transforms.conf REGEX → Cribl eval functions',
        ],
        warnings: [
          'Review complex regex patterns for accuracy',
          'Test field extractions with sample data before deploying',
          'Some Splunk-specific features may not have direct Cribl equivalents',
        ],
      });
      setIsTranslating(false);
    }, 2000);
  };

  const hasAnyConfig = taConfig.inputsConf || taConfig.propsConf || taConfig.transformsConf;

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
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-3xl font-bold">Splunk TA → Cribl Translator</h1>
          <Badge
            variant="outline"
            className="bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100"
          >
            BETA
          </Badge>
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
              <Label className="text-sm font-medium flex items-center gap-2">
                inputs.conf
                {taConfig.inputsConf && (
                  <Badge variant="secondary" className="text-xs">
                    ✓ Loaded
                  </Badge>
                )}
              </Label>
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
              <Label className="text-sm font-medium flex items-center gap-2">
                props.conf
                {taConfig.propsConf && (
                  <Badge variant="secondary" className="text-xs">
                    ✓ Loaded
                  </Badge>
                )}
              </Label>
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
              <Label className="text-sm font-medium flex items-center gap-2">
                transforms.conf (optional)
                {taConfig.transformsConf && (
                  <Badge variant="secondary" className="text-xs">
                    ✓ Loaded
                  </Badge>
                )}
              </Label>
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
              disabled={!hasAnyConfig || isTranslating}
              className="w-full"
              size="lg"
            >
              {isTranslating ? (
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
    </div>
  );
}
