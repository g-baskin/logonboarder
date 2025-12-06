// Documentation RAG tRPC Router
import { z } from 'zod';
import { createTRPCRouter, publicProcedure } from '@/server/api/trpc';
import { getRAGService } from '@/server/services/documentation-rag';

export const documentationRAGRouter = createTRPCRouter({
  // Initialize the RAG service by fetching documentation
  initialize: publicProcedure
    .input(
      z.object({
        fetchSplunk: z.boolean().default(true),
        fetchCribl: z.boolean().default(true),
      })
    )
    .mutation(async ({ input }) => {
      const ragService = getRAGService();
      await ragService.initialize(input);
      const stats = ragService.getStats();

      return {
        success: true,
        message: 'Documentation RAG service initialized',
        stats,
      };
    }),

  // Search documentation
  search: publicProcedure
    .input(
      z.object({
        query: z.string().min(1),
        type: z.enum(['splunk', 'cribl']).optional(),
        limit: z.number().min(1).max(50).default(10),
        filters: z
          .object({
            configFile: z.string().optional(),
            functionType: z.string().optional(),
            setting: z.string().optional(),
          })
          .optional(),
      })
    )
    .query(async ({ input }) => {
      const ragService = getRAGService();
      const response = await ragService.search(input);

      return {
        success: true,
        results: response.results.map((r) => ({
          id: r.chunk.id,
          type: r.chunk.type,
          title: r.chunk.title,
          content: r.chunk.content,
          url: r.chunk.url,
          section: r.chunk.section,
          metadata: r.chunk.metadata,
          relevanceScore: r.relevanceScore,
          highlights: r.highlights,
        })),
        summary: response.summary,
        relatedTopics: response.relatedTopics,
      };
    }),

  // Search for Splunk setting documentation
  searchSplunkSetting: publicProcedure
    .input(
      z.object({
        setting: z.string().min(1),
        configFile: z
          .enum([
            'inputs.conf',
            'props.conf',
            'transforms.conf',
            'fields.conf',
            'tags.conf',
            'eventtypes.conf',
            'savedsearches.conf',
            'macros.conf',
            'workflow_actions.conf',
            'indexes.conf',
          ])
          .optional(),
      })
    )
    .query(async ({ input }) => {
      const ragService = getRAGService();
      const response = await ragService.searchSplunkSetting(input.setting, input.configFile);

      return {
        success: true,
        results: response.results.map((r) => ({
          id: r.chunk.id,
          title: r.chunk.title,
          content: r.chunk.content,
          url: r.chunk.url,
          metadata: r.chunk.metadata,
          relevanceScore: r.relevanceScore,
        })),
        summary: response.summary,
      };
    }),

  // Search for Cribl function documentation
  searchCriblFunction: publicProcedure
    .input(
      z.object({
        functionType: z.enum([
          'auto_timestamp',
          'regex_extract',
          'parser',
          'eval',
          'mask',
          'drop',
          'grok',
          'lookup',
          'event_breaker',
          'aggregation',
          'sampling',
          'suppress',
        ]),
      })
    )
    .query(async ({ input }) => {
      const ragService = getRAGService();
      const response = await ragService.searchCriblFunction(input.functionType);

      return {
        success: true,
        results: response.results.map((r) => ({
          id: r.chunk.id,
          title: r.chunk.title,
          content: r.chunk.content,
          url: r.chunk.url,
          metadata: r.chunk.metadata,
          relevanceScore: r.relevanceScore,
        })),
        summary: response.summary,
      };
    }),

  // Get translation guidance
  getTranslationGuidance: publicProcedure
    .input(
      z.object({
        splunkSetting: z.string().min(1),
        splunkConfigFile: z.enum([
          'inputs.conf',
          'props.conf',
          'transforms.conf',
          'fields.conf',
          'tags.conf',
          'eventtypes.conf',
          'savedsearches.conf',
          'macros.conf',
          'workflow_actions.conf',
          'indexes.conf',
        ]),
        criblFunctionType: z
          .enum([
            'auto_timestamp',
            'regex_extract',
            'parser',
            'eval',
            'mask',
            'drop',
            'grok',
            'lookup',
            'event_breaker',
            'aggregation',
            'sampling',
            'suppress',
          ])
          .optional(),
      })
    )
    .query(async ({ input }) => {
      const ragService = getRAGService();
      const guidance = await ragService.getTranslationGuidance(
        input.splunkSetting,
        input.splunkConfigFile,
        input.criblFunctionType
      );

      return {
        success: true,
        splunkDocs: guidance.splunkDocs.map((r) => ({
          id: r.chunk.id,
          title: r.chunk.title,
          content: r.chunk.content,
          url: r.chunk.url,
        })),
        criblDocs: guidance.criblDocs.map((r) => ({
          id: r.chunk.id,
          title: r.chunk.title,
          content: r.chunk.content,
          url: r.chunk.url,
        })),
        guidance: guidance.guidance,
      };
    }),

  // Refresh documentation
  refresh: publicProcedure
    .input(
      z.object({
        type: z.enum(['splunk', 'cribl']),
      })
    )
    .mutation(async ({ input }) => {
      const ragService = getRAGService();
      await ragService.refresh(input.type);
      const stats = ragService.getStats();

      return {
        success: true,
        message: `${input.type} documentation refreshed`,
        stats,
      };
    }),

  // Get storage statistics
  getStats: publicProcedure.query(() => {
    const ragService = getRAGService();
    const stats = ragService.getStats();

    return {
      success: true,
      stats,
    };
  }),
});
