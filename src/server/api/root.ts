import { createTRPCRouter } from './trpc';
import { exampleRouter } from './routers/example';
import { analyzeRouter } from './routers/analyze';

export const appRouter = createTRPCRouter({
  example: exampleRouter,
  analyze: analyzeRouter,
});

export type AppRouter = typeof appRouter;
