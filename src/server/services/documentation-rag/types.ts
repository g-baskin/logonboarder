// Documentation RAG Type Definitions

export type DocumentationType = 'splunk' | 'cribl';

export type SplunkConfigFile =
  | 'inputs.conf'
  | 'props.conf'
  | 'transforms.conf'
  | 'fields.conf'
  | 'tags.conf'
  | 'eventtypes.conf'
  | 'savedsearches.conf'
  | 'macros.conf'
  | 'workflow_actions.conf'
  | 'indexes.conf';

export type CriblFunctionType =
  | 'auto_timestamp'
  | 'regex_extract'
  | 'parser'
  | 'eval'
  | 'mask'
  | 'drop'
  | 'grok'
  | 'lookup'
  | 'event_breaker'
  | 'aggregation'
  | 'sampling'
  | 'suppress';

export interface DocumentationChunk {
  id: string;
  type: DocumentationType;
  title: string;
  content: string;
  url: string;
  section: string;
  metadata: Record<string, string>;
  createdAt: Date;
  updatedAt: Date;
}

export interface SplunkDocumentation extends DocumentationChunk {
  type: 'splunk';
  configFile?: SplunkConfigFile;
  setting?: string; // e.g., "SHOULD_LINEMERGE", "KV_MODE"
  stanzaType?: string; // e.g., "[source::...]", "[sourcetype]"
}

export interface CriblDocumentation extends DocumentationChunk {
  type: 'cribl';
  functionType?: CriblFunctionType;
  configSection?: 'routes' | 'pipelines' | 'functions' | 'packs';
}

export interface DocumentationQuery {
  query: string;
  type?: DocumentationType;
  limit?: number;
  filters?: {
    configFile?: SplunkConfigFile;
    functionType?: CriblFunctionType;
    setting?: string;
  };
}

export interface DocumentationSearchResult {
  chunk: DocumentationChunk;
  relevanceScore: number;
  highlights?: string[];
}

export interface RAGResponse {
  results: DocumentationSearchResult[];
  summary?: string;
  relatedTopics?: string[];
}

// Storage interface - can be implemented with different backends
export interface DocumentationStorage {
  // Store a documentation chunk
  store(chunk: DocumentationChunk): Promise<void>;

  // Store multiple chunks in batch
  storeBatch(chunks: DocumentationChunk[]): Promise<void>;

  // Search for documentation
  search(query: DocumentationQuery): Promise<DocumentationSearchResult[]>;

  // Get documentation by ID
  getById(id: string): Promise<DocumentationChunk | null>;

  // Delete documentation by ID
  delete(id: string): Promise<void>;

  // Clear all documentation of a specific type
  clearType(type: DocumentationType): Promise<void>;
}
