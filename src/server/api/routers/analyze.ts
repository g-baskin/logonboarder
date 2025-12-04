import { z } from 'zod';
import { createTRPCRouter, publicProcedure } from '../trpc';
import { analyzePaths } from '@/server/services/path-analyzer';
import { scanPathsForSensitiveData } from '@/server/services/sensitive-scanner';
import { generateConfigForSIEM } from '@/server/services/generators';
import { exportAsTxt } from '@/server/services/exporter';
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

const pathInputSchema = z.object({
  pathsText: z.string().min(1, 'Please enter at least one path'),
  siem: siemEnum.default('splunk'),
  runSensitiveScan: z.boolean().default(true),
  includeDomainsInConfigs: z.boolean().default(false),
  outputFormat: z.enum(['zip', 'txt']).default('zip'),
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
      const pathAnalysis = analyzePaths(paths);

      // Step 2: Scan for sensitive data
      const sensitiveFindings = input.runSensitiveScan ? scanPathsForSensitiveData(paths) : [];

      // Step 3: Generate config for selected SIEM
      const generatedConfig = generateConfigForSIEM(
        pathAnalysis,
        input.siem as SIEM,
        sensitiveFindings
      );

      return {
        success: true,
        pathAnalysis,
        sensitiveFindings,
        generatedConfig,
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
});
