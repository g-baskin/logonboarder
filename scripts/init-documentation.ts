#!/usr/bin/env tsx
/**
 * Initialize Documentation RAG Service
 * This script fetches and stores Splunk and Cribl documentation
 *
 * Usage:
 *   npx tsx scripts/init-documentation.ts
 *   npx tsx scripts/init-documentation.ts --splunk-only
 *   npx tsx scripts/init-documentation.ts --cribl-only
 */

import { getRAGService } from '../src/server/services/documentation-rag';

async function main() {
  const args = process.argv.slice(2);
  const splunkOnly = args.includes('--splunk-only');
  const criblOnly = args.includes('--cribl-only');

  const fetchSplunk = !criblOnly;
  const fetchCribl = !splunkOnly;

  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║   Documentation RAG Service Initialization       ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');

  const ragService = getRAGService();

  try {
    console.log('Starting documentation fetch...');
    console.log(`  - Fetch Splunk docs: ${fetchSplunk ? '✓' : '✗'}`);
    console.log(`  - Fetch Cribl docs: ${fetchCribl ? '✓' : '✗'}`);
    console.log('');

    await ragService.initialize({
      fetchSplunk,
      fetchCribl,
    });

    console.log('');
    console.log('✓ Documentation RAG service initialized successfully!');
    console.log('');

    const stats = ragService.getStats();
    console.log('Storage Statistics:');
    console.log(`  Total chunks: ${stats.total}`);
    console.log(`  Splunk chunks: ${stats.splunk}`);
    console.log(`  Cribl chunks: ${stats.cribl}`);
    console.log('');

    // Test search
    console.log('Testing search functionality...');
    console.log('');

    if (fetchSplunk) {
      console.log('Searching for "SHOULD_LINEMERGE"...');
      const splunkTest = await ragService.searchSplunkSetting('SHOULD_LINEMERGE', 'props.conf');
      console.log(`  Found ${splunkTest.results.length} results`);
      if (splunkTest.results.length > 0) {
        console.log(`  Top result: ${splunkTest.results[0].chunk.title}`);
        console.log(`  Summary: ${splunkTest.summary?.slice(0, 100)}...`);
      }
      console.log('');
    }

    if (fetchCribl) {
      console.log('Searching for "regex_extract"...');
      const criblTest = await ragService.searchCriblFunction('regex_extract');
      console.log(`  Found ${criblTest.results.length} results`);
      if (criblTest.results.length > 0) {
        console.log(`  Top result: ${criblTest.results[0].chunk.title}`);
        console.log(`  Summary: ${criblTest.summary?.slice(0, 100)}...`);
      }
      console.log('');
    }

    console.log('✓ All tests passed!');
    process.exit(0);
  } catch (error) {
    console.error('');
    console.error('✗ Error initializing documentation RAG service:');
    console.error(error);
    process.exit(1);
  }
}

main();
