import { z } from 'zod';
import { createTRPCRouter, publicProcedure } from '../trpc';
import { analyzePaths } from '@/server/services/path-analyzer';
import { scanPathsForSensitiveData } from '@/server/services/sensitive-scanner';
import { generateConfigForSIEM } from '@/server/services/generators';
import { exportAsTxt } from '@/server/services/exporter';
import { analyzeLogSample } from '@/server/services/log-sample-analyzer';
import type { AnalyzeResponse, SIEM } from '@/types/logonboard';

// Supported SIEM platforms
const siemEnum = z.enum(['splunk', 'elastic', 'sentinel', 'qradar', 'cribl']);

const analyzeInputSchema = z.object({
  paths: z.array(z.string()).min(1, 'At least one path is required'),
  siem: siemEnum,
  options: z.object({
    runSensitiveScan: z.boolean().default(true),
    includeDomainsInConfigs: z.boolean().default(false),
    outputFormat: z.enum(['zip', 'txt']).default('zip'),
  }),
});

// Schema for field extraction
const fieldExtractionSchema = z.object({
  name: z.string(),
  sampleValue: z.string(),
  type: z.enum(['string', 'number', 'boolean', 'object', 'array', 'null']),
  nested: z.boolean().optional(),
  path: z.string().optional(),
});

// Schema for log sample analysis (optional enhancement)
const sampleAnalysisSchema = z
  .object({
    timeFormat: z.string().nullable(),
    timePrefix: z.string().nullable(),
    lineBreaker: z.string(),
    kvMode: z.enum(['auto', 'json', 'none']),
    maxTimestampLookahead: z.number(),
    detectedFields: z.array(z.string()),
    extractedFields: z.array(fieldExtractionSchema),
    confidence: z.enum(['high', 'medium', 'low']),
    sampleType: z.enum(['json', 'kv', 'syslog', 'apache', 'csv', 'unknown']),
    rawPattern: z.string().nullable(),
    suggestedPaths: z.array(z.string()),
    detectedVendor: z.string().nullable(),
    suggestedSourcetype: z.string().nullable(),
    // New platform/format detection
    detectedPlatform: z.enum([
      'windows',
      'linux',
      'unix',
      'macos',
      'aws',
      'azure',
      'gcp',
      'docker',
      'kubernetes',
      'cloud',
      'unknown',
    ]),
    detectedFormat: z.enum([
      'json',
      'xml',
      'csv',
      'cef',
      'leef',
      'windows-evtx',
      'syslog',
      'apache',
      'nginx',
      'iis',
      'kv',
      'custom',
      'unknown',
    ]),
    splunkInputMethod: z.enum([
      'monitor',
      'hec',
      'scripted',
      'wmi',
      'powershell',
      's3',
      'kinesis',
      'cloudwatch',
      'azure-blob',
      'gcp-pubsub',
    ]),
    elasticInputMethod: z.enum([
      'filebeat',
      'filebeat-aws',
      'filebeat-azure',
      'filebeat-gcp',
      'metricbeat',
      'winlogbeat',
      'functionbeat',
      'logstash',
      'elastic-agent',
    ]),
    sentinelInputMethod: z.enum([
      'ama',
      'log-analytics',
      'data-connector',
      'syslog',
      'cef',
      'api',
      'logstash',
      'function-app',
    ]),
    qradarInputMethod: z.enum([
      'log-source',
      'syslog',
      'snmp',
      'jdbc',
      'wincollect',
      'api',
      'universal-cloud-rest',
    ]),
    criblInputMethod: z.enum([
      'syslog',
      'http',
      's3',
      'kinesis',
      'kafka',
      'splunk-hec',
      'elastic-bulk',
      'file-monitor',
    ]),
    inputMethodNotes: z.string().optional(),
  })
  .optional();

const pathInputSchema = z.object({
  pathsText: z.string().min(1, 'Please enter at least one path'),
  siem: siemEnum.default('splunk'),
  runSensitiveScan: z.boolean().default(true),
  includeDomainsInConfigs: z.boolean().default(false),
  outputFormat: z.enum(['zip', 'txt']).default('zip'),
  sampleAnalysis: sampleAnalysisSchema,
});

export const analyzeRouter = createTRPCRouter({
  // Analyze paths and generate configs
  analyze: publicProcedure
    .input(analyzeInputSchema)
    .mutation(async ({ input }): Promise<AnalyzeResponse> => {
      const { paths, siem, options } = input;

      // Step 1: Analyze paths
      const pathAnalysis = analyzePaths(paths);

      // Step 2: Scan for sensitive data (if enabled)
      const sensitiveFindings = options.runSensitiveScan ? scanPathsForSensitiveData(paths) : [];

      // Step 3: Generate config for selected SIEM
      const generatedConfig = generateConfigForSIEM(pathAnalysis, siem as SIEM, sensitiveFindings);

      return {
        success: true,
        pathAnalysis,
        sensitiveFindings,
        generatedConfig,
      };
    }),

  // Simplified endpoint that accepts text input
  analyzeText: publicProcedure
    .input(pathInputSchema)
    .mutation(async ({ input }): Promise<AnalyzeResponse> => {
      // Parse paths from text (one per line)
      const paths = input.pathsText
        .split('\n')
        .map((p) => p.trim())
        .filter((p) => p.length > 0);

      if (paths.length === 0) {
        throw new Error('No valid paths provided');
      }

      // Step 1: Analyze paths
      let pathAnalysis = analyzePaths(paths);

      // Step 1.5: Override sourcetype with detected sourcetype from sample analysis
      if (input.sampleAnalysis?.suggestedSourcetype) {
        pathAnalysis = pathAnalysis.map((result) => ({
          ...result,
          sourcetype: input.sampleAnalysis!.suggestedSourcetype!,
          confidence: 'high',
        }));
      }

      // Step 2: Scan for sensitive data
      const sensitiveFindings = input.runSensitiveScan ? scanPathsForSensitiveData(paths) : [];

      // Step 3: Generate configs for ALL SIEMs (for multi-SIEM support)
      const allSiems: SIEM[] = ['splunk', 'elastic', 'sentinel', 'qradar', 'cribl'];

      // Generate config for the primary (selected) SIEM first
      const primaryConfig = generateConfigForSIEM(
        pathAnalysis,
        input.siem as SIEM,
        sensitiveFindings,
        input.sampleAnalysis
      );

      // Generate configs for all other SIEMs and add them to the primary config
      for (const siem of allSiems) {
        if (siem !== input.siem) {
          const siemConfig = generateConfigForSIEM(
            pathAnalysis,
            siem,
            sensitiveFindings,
            input.sampleAnalysis
          );

          // Add the SIEM-specific config to the primary config
          if (siem === 'elastic' && siemConfig.elastic) {
            primaryConfig.elastic = siemConfig.elastic;
          } else if (siem === 'sentinel' && siemConfig.sentinel) {
            primaryConfig.sentinel = siemConfig.sentinel;
          } else if (siem === 'qradar' && siemConfig.qradar) {
            primaryConfig.qradar = siemConfig.qradar;
          } else if (siem === 'cribl' && siemConfig.cribl) {
            primaryConfig.cribl = siemConfig.cribl;
          }
        }
      }

      // Set the primary SIEM marker
      primaryConfig.siem = input.siem as SIEM;

      return {
        success: true,
        pathAnalysis,
        sensitiveFindings,
        generatedConfig: primaryConfig,
      };
    }),

  // Get config as downloadable text
  getConfigText: publicProcedure
    .input(
      z.object({
        inputsConf: z.string(),
        propsConf: z.string(),
        transformsConf: z.string(),
        readme: z.string(),
        metadata: z.any(),
      })
    )
    .query(({ input }) => {
      return exportAsTxt({
        inputsConf: input.inputsConf,
        propsConf: input.propsConf,
        transformsConf: input.transformsConf,
        readme: input.readme,
        metadata: input.metadata,
      });
    }),

  // Preview a single path analysis
  previewPath: publicProcedure.input(z.object({ path: z.string().min(1) })).query(({ input }) => {
    const results = analyzePaths([input.path]);
    return results[0] || null;
  }),

  // Analyze a log sample to detect TIME_FORMAT, LINE_BREAKER, etc.
  analyzeLogSample: publicProcedure
    .input(z.object({ sample: z.string().min(1, 'Please provide a log sample') }))
    .mutation(({ input }) => {
      return analyzeLogSample(input.sample);
    }),
});
