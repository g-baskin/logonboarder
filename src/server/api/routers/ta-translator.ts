import { z } from 'zod';
import { createTRPCRouter, publicProcedure } from '../trpc';
import { translateTAToCribl } from '@/server/services/ta-translator';
import type { CriblTranslation, TAConfig } from '@/server/services/ta-translator';

const taConfigSchema = z.object({
  inputsConf: z.string().optional(),
  propsConf: z.string().optional(),
  transformsConf: z.string().optional(),
});

export const taTranslatorRouter = createTRPCRouter({
  // Translate Splunk TA configs to Cribl Stream
  translate: publicProcedure
    .input(taConfigSchema)
    .mutation(async ({ input }): Promise<CriblTranslation> => {
      // Validate that at least one config is provided
      if (!input.inputsConf && !input.propsConf && !input.transformsConf) {
        throw new Error(
          'At least one Splunk TA configuration file must be provided (inputs.conf, props.conf, or transforms.conf)'
        );
      }

      const taConfig: TAConfig = {
        inputsConf: input.inputsConf,
        propsConf: input.propsConf,
        transformsConf: input.transformsConf,
      };

      // Perform translation (now async with RAG integration)
      const translation = await translateTAToCribl(taConfig);

      return translation;
    }),

  // Preview translation of a single config file
  previewConfig: publicProcedure
    .input(
      z.object({
        configType: z.enum(['inputs', 'props', 'transforms']),
        content: z.string().min(1),
      })
    )
    .query(async ({ input }) => {
      const taConfig: TAConfig = {};

      // Only set the relevant config based on type
      if (input.configType === 'inputs') {
        taConfig.inputsConf = input.content;
      } else if (input.configType === 'props') {
        taConfig.propsConf = input.content;
      } else if (input.configType === 'transforms') {
        taConfig.transformsConf = input.content;
      }

      const translation = await translateTAToCribl(taConfig);

      return {
        success: true,
        preview: translation,
      };
    }),
});
