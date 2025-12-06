import { createTRPCRouter } from './trpc';
import { exampleRouter } from './routers/example';
import { analyzeRouter } from './routers/analyze';
import { taTranslatorRouter } from './routers/ta-translator';
import { documentationRAGRouter } from './routers/documentation-rag';

export const appRouter = createTRPCRouter({
  example: exampleRouter,
  analyze: analyzeRouter,
  taTranslator: taTranslatorRouter,
  documentationRAG: documentationRAGRouter,
});

export type AppRouter = typeof appRouter;
