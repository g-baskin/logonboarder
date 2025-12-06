// In-Memory Documentation Storage
// This is a simple implementation that can be replaced with a vector database later
import type {
  DocumentationStorage,
  DocumentationChunk,
  DocumentationQuery,
  DocumentationSearchResult,
} from '../types';

export class InMemoryDocumentationStorage implements DocumentationStorage {
  private chunks: Map<string, DocumentationChunk> = new Map();

  async store(chunk: DocumentationChunk): Promise<void> {
    this.chunks.set(chunk.id, chunk);
  }

  async storeBatch(chunks: DocumentationChunk[]): Promise<void> {
    for (const chunk of chunks) {
      this.chunks.set(chunk.id, chunk);
    }
  }

  async search(query: DocumentationQuery): Promise<DocumentationSearchResult[]> {
    const results: DocumentationSearchResult[] = [];
    const queryLower = query.query.toLowerCase();
    const queryTerms = queryLower.split(/\s+/).filter((t) => t.length > 2);

    for (const chunk of this.chunks.values()) {
      // Filter by type if specified
      if (query.type && chunk.type !== query.type) {
        continue;
      }

      // Filter by config file if specified (Splunk)
      if (
        query.filters?.configFile &&
        'configFile' in chunk &&
        chunk.configFile !== query.filters.configFile
      ) {
        continue;
      }

      // Filter by function type if specified (Cribl)
      if (
        query.filters?.functionType &&
        'functionType' in chunk &&
        chunk.functionType !== query.filters.functionType
      ) {
        continue;
      }

      // Filter by setting if specified (Splunk)
      if (query.filters?.setting && 'setting' in chunk && chunk.setting !== query.filters.setting) {
        continue;
      }

      // Calculate relevance score
      const score = this.calculateRelevanceScore(chunk, queryLower, queryTerms);

      if (score > 0) {
        results.push({
          chunk,
          relevanceScore: score,
          highlights: this.extractHighlights(chunk, queryTerms),
        });
      }
    }

    // Sort by relevance score (descending)
    results.sort((a, b) => b.relevanceScore - a.relevanceScore);

    // Limit results
    const limit = query.limit || 10;
    return results.slice(0, limit);
  }

  async getById(id: string): Promise<DocumentationChunk | null> {
    return this.chunks.get(id) || null;
  }

  async delete(id: string): Promise<void> {
    this.chunks.delete(id);
  }

  async clearType(type: 'splunk' | 'cribl'): Promise<void> {
    for (const [id, chunk] of this.chunks.entries()) {
      if (chunk.type === type) {
        this.chunks.delete(id);
      }
    }
  }

  /**
   * Calculate relevance score using keyword matching
   * This is a simple implementation - can be replaced with embeddings later
   */
  private calculateRelevanceScore(
    chunk: DocumentationChunk,
    queryLower: string,
    queryTerms: string[]
  ): number {
    let score = 0;

    const titleLower = chunk.title.toLowerCase();
    const contentLower = chunk.content.toLowerCase();
    const sectionLower = chunk.section.toLowerCase();

    // Exact match in title - highest weight
    if (titleLower.includes(queryLower)) {
      score += 100;
    }

    // Exact match in section
    if (sectionLower.includes(queryLower)) {
      score += 50;
    }

    // Exact match in content
    if (contentLower.includes(queryLower)) {
      score += 25;
    }

    // Term matching in title
    for (const term of queryTerms) {
      if (titleLower.includes(term)) {
        score += 10;
      }
      if (sectionLower.includes(term)) {
        score += 5;
      }
      if (contentLower.includes(term)) {
        score += 2;
      }
    }

    // Metadata matching
    for (const [key, value] of Object.entries(chunk.metadata)) {
      const valueLower = value.toLowerCase();
      if (valueLower.includes(queryLower)) {
        score += 15;
      }
      for (const term of queryTerms) {
        if (valueLower.includes(term)) {
          score += 3;
        }
      }
    }

    return score;
  }

  /**
   * Extract highlighted snippets from content
   */
  private extractHighlights(chunk: DocumentationChunk, queryTerms: string[]): string[] {
    const highlights: string[] = [];
    const contentLower = chunk.content.toLowerCase();

    for (const term of queryTerms) {
      const index = contentLower.indexOf(term);
      if (index !== -1) {
        // Extract context around the term (50 chars before and after)
        const start = Math.max(0, index - 50);
        const end = Math.min(chunk.content.length, index + term.length + 50);
        let snippet = chunk.content.slice(start, end);

        if (start > 0) snippet = '...' + snippet;
        if (end < chunk.content.length) snippet = snippet + '...';

        highlights.push(snippet);
      }
    }

    return highlights.slice(0, 3); // Return up to 3 highlights
  }

  /**
   * Get statistics about stored documentation
   */
  getStats(): {
    total: number;
    splunk: number;
    cribl: number;
  } {
    let splunk = 0;
    let cribl = 0;

    for (const chunk of this.chunks.values()) {
      if (chunk.type === 'splunk') splunk++;
      if (chunk.type === 'cribl') cribl++;
    }

    return {
      total: this.chunks.size,
      splunk,
      cribl,
    };
  }
}
