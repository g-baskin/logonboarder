// Splunk Documentation Fetcher
import type { SplunkDocumentation } from '../types';
import { splunkPropsKnowledgeBase } from '../knowledge-bases/splunk-props-kb';

/**
 * Fetches Splunk documentation from curated knowledge bases
 * This uses pre-curated content based on official Splunk documentation
 */
export class SplunkDocsFetcher {
  /**
   * Fetch documentation for all config files from curated knowledge base
   */
  async fetchAllConfigFileDocs(): Promise<SplunkDocumentation[]> {
    console.log('Loading Splunk documentation from curated knowledge base...');

    const docs: SplunkDocumentation[] = [];
    const now = new Date();

    // Load props.conf knowledge base
    for (const doc of splunkPropsKnowledgeBase) {
      docs.push({
        ...doc,
        id: `splunk-${doc.configFile}-${doc.setting}-${Date.now()}-${Math.random()}`,
        createdAt: now,
        updatedAt: now,
      });
    }

    console.log(`Loaded ${docs.length} Splunk documentation entries`);
    return docs;
  }
}
