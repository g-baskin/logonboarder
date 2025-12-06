// Main Documentation RAG Service
import { SplunkDocsFetcher } from './fetchers/splunk-docs-fetcher';
import { CriblDocsFetcher } from './fetchers/cribl-docs-fetcher';
import { InMemoryDocumentationStorage } from './storage/in-memory-storage';
import type {
  DocumentationQuery,
  DocumentationSearchResult,
  RAGResponse,
  SplunkConfigFile,
  CriblFunctionType,
} from './types';

export class DocumentationRAGService {
  private storage: InMemoryDocumentationStorage;
  private splunkFetcher: SplunkDocsFetcher;
  private criblFetcher: CriblDocsFetcher;
  private isInitialized = false;

  constructor() {
    this.storage = new InMemoryDocumentationStorage();
    this.splunkFetcher = new SplunkDocsFetcher();
    this.criblFetcher = new CriblDocsFetcher();
  }

  /**
   * Initialize the RAG service by fetching and storing documentation
   * This should be called once on startup or manually when needed
   */
  async initialize(options?: { fetchSplunk?: boolean; fetchCribl?: boolean }): Promise<void> {
    const { fetchSplunk = true, fetchCribl = true } = options || {};

    console.log('Initializing Documentation RAG Service...');

    if (fetchSplunk) {
      console.log('Fetching Splunk documentation...');
      try {
        const splunkDocs = await this.splunkFetcher.fetchAllConfigFileDocs();
        await this.storage.storeBatch(splunkDocs);
        console.log(`Stored ${splunkDocs.length} Splunk documentation chunks`);
      } catch (error) {
        console.error('Error fetching Splunk documentation:', error);
      }
    }

    if (fetchCribl) {
      console.log('Fetching Cribl documentation...');
      try {
        const criblFunctionDocs = await this.criblFetcher.fetchAllFunctionDocs();
        const criblGeneralDocs = await this.criblFetcher.fetchGeneralDocs();
        const allCriblDocs = [...criblFunctionDocs, ...criblGeneralDocs];
        await this.storage.storeBatch(allCriblDocs);
        console.log(`Stored ${allCriblDocs.length} Cribl documentation chunks`);
      } catch (error) {
        console.error('Error fetching Cribl documentation:', error);
      }
    }

    this.isInitialized = true;
    console.log('Documentation RAG Service initialized');
    console.log('Storage stats:', this.storage.getStats());
  }

  /**
   * Search documentation
   */
  async search(query: DocumentationQuery): Promise<RAGResponse> {
    if (!this.isInitialized) {
      console.warn('RAG service not initialized. Call initialize() first for best results.');
    }

    const results = await this.storage.search(query);

    return {
      results,
      summary: this.generateSummary(results),
      relatedTopics: this.extractRelatedTopics(results),
    };
  }

  /**
   * Search for Splunk setting documentation
   */
  async searchSplunkSetting(setting: string, configFile?: SplunkConfigFile): Promise<RAGResponse> {
    return this.search({
      query: setting,
      type: 'splunk',
      filters: {
        configFile,
        setting,
      },
      limit: 5,
    });
  }

  /**
   * Search for Cribl function documentation
   */
  async searchCriblFunction(functionType: CriblFunctionType): Promise<RAGResponse> {
    return this.search({
      query: functionType,
      type: 'cribl',
      filters: {
        functionType,
      },
      limit: 5,
    });
  }

  /**
   * Get documentation for translating a specific Splunk setting to Cribl
   */
  async getTranslationGuidance(
    splunkSetting: string,
    splunkConfigFile: SplunkConfigFile,
    criblFunctionType?: CriblFunctionType
  ): Promise<{
    splunkDocs: DocumentationSearchResult[];
    criblDocs: DocumentationSearchResult[];
    guidance: string;
  }> {
    // Search for Splunk documentation
    const splunkResults = await this.searchSplunkSetting(splunkSetting, splunkConfigFile);

    // Search for Cribl documentation if function type is provided
    let criblResults: RAGResponse | null = null;
    if (criblFunctionType) {
      criblResults = await this.searchCriblFunction(criblFunctionType);
    }

    // Generate translation guidance
    const guidance = this.generateTranslationGuidance(
      splunkResults.results,
      criblResults?.results || []
    );

    return {
      splunkDocs: splunkResults.results,
      criblDocs: criblResults?.results || [],
      guidance,
    };
  }

  /**
   * Refresh documentation for a specific type
   */
  async refresh(type: 'splunk' | 'cribl'): Promise<void> {
    console.log(`Refreshing ${type} documentation...`);
    await this.storage.clearType(type);

    if (type === 'splunk') {
      const splunkDocs = await this.splunkFetcher.fetchAllConfigFileDocs();
      await this.storage.storeBatch(splunkDocs);
      console.log(`Refreshed ${splunkDocs.length} Splunk documentation chunks`);
    } else if (type === 'cribl') {
      const criblFunctionDocs = await this.criblFetcher.fetchAllFunctionDocs();
      const criblGeneralDocs = await this.criblFetcher.fetchGeneralDocs();
      const allCriblDocs = [...criblFunctionDocs, ...criblGeneralDocs];
      await this.storage.storeBatch(allCriblDocs);
      console.log(`Refreshed ${allCriblDocs.length} Cribl documentation chunks`);
    }
  }

  /**
   * Get storage statistics
   */
  getStats() {
    return this.storage.getStats();
  }

  /**
   * Generate a summary from search results
   */
  private generateSummary(results: DocumentationSearchResult[]): string {
    if (results.length === 0) {
      return 'No documentation found for this query.';
    }

    const topResult = results[0];
    const summary = topResult.chunk.content.slice(0, 200);
    const hasMore = results.length > 1;

    return summary + (hasMore ? `... (${results.length - 1} more results available)` : '');
  }

  /**
   * Extract related topics from search results
   */
  private extractRelatedTopics(results: DocumentationSearchResult[]): string[] {
    const topics = new Set<string>();

    for (const result of results.slice(0, 5)) {
      // Get related settings/functions from metadata
      if ('setting' in result.chunk && result.chunk.setting) {
        topics.add(result.chunk.setting);
      }
      if ('functionType' in result.chunk && result.chunk.functionType) {
        topics.add(result.chunk.functionType);
      }
    }

    return Array.from(topics).slice(0, 5);
  }

  /**
   * Generate translation guidance based on documentation
   */
  private generateTranslationGuidance(
    splunkDocs: DocumentationSearchResult[],
    criblDocs: DocumentationSearchResult[]
  ): string {
    const parts: string[] = [];

    if (splunkDocs.length > 0) {
      const topSplunkDoc = splunkDocs[0];
      parts.push(`**Splunk Context:**\n${topSplunkDoc.chunk.content.slice(0, 300)}`);
    }

    if (criblDocs.length > 0) {
      const topCriblDoc = criblDocs[0];
      parts.push(`\n**Cribl Equivalent:**\n${topCriblDoc.chunk.content.slice(0, 300)}`);
    }

    if (parts.length === 0) {
      return 'No documentation available for this translation. Using built-in knowledge.';
    }

    return parts.join('\n\n');
  }
}

// Export singleton instance
let ragServiceInstance: DocumentationRAGService | null = null;

export function getRAGService(): DocumentationRAGService {
  if (!ragServiceInstance) {
    ragServiceInstance = new DocumentationRAGService();
  }
  return ragServiceInstance;
}

// Export types
export * from './types';
