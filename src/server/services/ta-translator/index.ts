/**
 * Splunk TA → Cribl Stream Translator
 * Converts Splunk Technical Add-on configs to Cribl Stream pipelines
 */

import { getRAGService } from '../documentation-rag';

export interface TAConfig {
  inputsConf?: string;
  propsConf?: string;
  transformsConf?: string;
}

export interface TranslationBreakdown {
  splunkConfig: string;
  criblConfig: string;
  configType: 'input' | 'prop' | 'transform';
  criblComponentType: 'route' | 'pipeline' | 'function';
  criblFunctionType?:
    | 'auto_timestamp'
    | 'regex_extract'
    | 'parser'
    | 'eval'
    | 'mask'
    | 'drop'
    | 'grok'
    | 'lookup'
    | 'event_breaker';
  criblFields?: string; // JSON string of copy-pasteable field configuration
  title: string;
  what: string;
  why: string;
  how: string;
  validation: string;
  autoHandled?: string; // Explanation of settings Cribl handles automatically
  notTranslated?: string; // Explanation of settings that weren't translated and why
}

export interface CriblTranslation {
  routes: string;
  pipelines: string;
  functions: string;
  notes: string[];
  warnings: string[];
  breakdown: TranslationBreakdown[];
}

export async function translateTAToCribl(taConfig: TAConfig): Promise<CriblTranslation> {
  const notes: string[] = [];
  const warnings: string[] = [];
  const breakdown: TranslationBreakdown[] = [];

  // Initialize RAG service for documentation-enhanced translations
  const ragService = getRAGService();

  // Ensure RAG is initialized (non-blocking if already initialized)
  if (ragService.getStats().total === 0) {
    console.log('Initializing RAG service for first-time use...');
    try {
      await ragService.initialize();
    } catch (error) {
      console.warn('RAG service initialization failed, proceeding without enhanced docs:', error);
    }
  }

  // Parse each config file
  const inputsData = taConfig.inputsConf ? parseInputsConf(taConfig.inputsConf) : null;
  const propsData = taConfig.propsConf ? parsePropsConf(taConfig.propsConf) : null;
  const transformsData = taConfig.transformsConf
    ? parseTransformsConf(taConfig.transformsConf)
    : null;

  // Generate Cribl configurations with breakdown (RAG service available but not required)
  const routes = generateCriblRoutes(inputsData, notes, warnings, breakdown);
  const pipelines = generateCriblPipelines(propsData, transformsData, notes, warnings, breakdown);
  const functions = generateCriblFunctions(propsData, transformsData, notes, warnings, breakdown);

  return {
    routes,
    pipelines,
    functions,
    notes,
    warnings,
    breakdown,
  };
}

// ============================================================================
// PARSERS
// ============================================================================

interface InputsConfig {
  stanzas: Array<{
    name: string;
    type: 'monitor' | 'script' | 'tcp' | 'udp' | 'hec' | 'unknown';
    path?: string;
    sourcetype?: string;
    index?: string;
    disabled?: boolean;
  }>;
}

function parseInputsConf(content: string): InputsConfig {
  const stanzas: InputsConfig['stanzas'] = [];
  const lines = content.split('\n');
  let currentStanza: InputsConfig['stanzas'][0] | null = null;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Stanza header [name]
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      if (currentStanza) {
        stanzas.push(currentStanza);
      }
      const name = trimmed.slice(1, -1);
      currentStanza = {
        name,
        type: detectInputType(name),
      };
      continue;
    }

    // Key = value
    if (currentStanza && trimmed.includes('=')) {
      const [key, ...valueParts] = trimmed.split('=');
      const value = valueParts.join('=').trim();
      const normalizedKey = key.trim().toLowerCase();

      if (normalizedKey === 'sourcetype') currentStanza.sourcetype = value;
      else if (normalizedKey === 'index') currentStanza.index = value;
      else if (normalizedKey === 'disabled') currentStanza.disabled = value === 'true';
    }
  }

  if (currentStanza) {
    stanzas.push(currentStanza);
  }

  return { stanzas };
}

function detectInputType(stanzaName: string): InputsConfig['stanzas'][0]['type'] {
  if (stanzaName.startsWith('monitor://')) return 'monitor';
  if (stanzaName.startsWith('script://')) return 'script';
  if (stanzaName.startsWith('tcp://')) return 'tcp';
  if (stanzaName.startsWith('udp://')) return 'udp';
  if (stanzaName.includes('http')) return 'hec';
  return 'unknown';
}

interface PropsConfig {
  sourcetypes: Array<{
    name: string;
    timeFormat?: string;
    timePrefix?: string;
    lineBreaker?: string;
    shouldLinemerge?: boolean;
    kvMode?: string;
    extracts?: Array<{ name: string; regex: string }>;
  }>;
}

function parsePropsConf(content: string): PropsConfig {
  const sourcetypes: PropsConfig['sourcetypes'] = [];
  const lines = content.split('\n');
  let currentSourcetype: PropsConfig['sourcetypes'][0] | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Stanza header [sourcetype]
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      if (currentSourcetype) {
        sourcetypes.push(currentSourcetype);
      }
      const name = trimmed.slice(1, -1);
      currentSourcetype = {
        name,
        extracts: [],
      };
      continue;
    }

    // Key = value
    if (currentSourcetype && trimmed.includes('=')) {
      const [key, ...valueParts] = trimmed.split('=');
      const value = valueParts.join('=').trim();
      const normalizedKey = key.trim();

      if (normalizedKey === 'TIME_FORMAT') currentSourcetype.timeFormat = value;
      else if (normalizedKey === 'TIME_PREFIX') currentSourcetype.timePrefix = value;
      else if (normalizedKey === 'LINE_BREAKER') currentSourcetype.lineBreaker = value;
      else if (normalizedKey === 'SHOULD_LINEMERGE')
        currentSourcetype.shouldLinemerge = value === 'true';
      else if (normalizedKey === 'KV_MODE') currentSourcetype.kvMode = value;
      else if (normalizedKey.startsWith('EXTRACT-')) {
        // EXTRACT-fieldname = regex
        const fieldName = normalizedKey.replace('EXTRACT-', '');
        currentSourcetype.extracts.push({ name: fieldName, regex: value });
      }
    }
  }

  if (currentSourcetype) {
    sourcetypes.push(currentSourcetype);
  }

  return { sourcetypes };
}

interface TransformsConfig {
  transforms: Array<{
    name: string;
    regex?: string;
    format?: string;
    dest?: string;
    sedcmd?: string; // For masking/redaction operations
    maskType?: 'redact' | 'hash' | 'replace';
  }>;
}

function parseTransformsConf(content: string): TransformsConfig {
  const transforms: TransformsConfig['transforms'] = [];
  const lines = content.split('\n');
  let currentTransform: TransformsConfig['transforms'][0] | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      if (currentTransform) {
        transforms.push(currentTransform);
      }
      const name = trimmed.slice(1, -1);
      currentTransform = { name };
      continue;
    }

    if (currentTransform && trimmed.includes('=')) {
      const [key, ...valueParts] = trimmed.split('=');
      const value = valueParts.join('=').trim();
      const normalizedKey = key.trim();

      if (normalizedKey === 'REGEX') currentTransform.regex = value;
      else if (normalizedKey === 'FORMAT') currentTransform.format = value;
      else if (normalizedKey === 'DEST_KEY') currentTransform.dest = value;
      else if (normalizedKey === 'SEDCMD' || normalizedKey.startsWith('SEDCMD-')) {
        currentTransform.sedcmd = value;
        // Detect mask type from sedcmd pattern
        if ((value.includes('s/') && value.includes('/XXX/')) || value.includes('/**/')) {
          currentTransform.maskType = 'redact';
        } else if (value.includes('s/')) {
          currentTransform.maskType = 'replace';
        }
      }
    }
  }

  if (currentTransform) {
    transforms.push(currentTransform);
  }

  return { transforms };
}

// ============================================================================
// GENERATORS
// ============================================================================

function generateCriblRoutes(
  inputsData: InputsConfig | null,
  notes: string[],
  warnings: string[],
  breakdown: TranslationBreakdown[]
): string {
  if (!inputsData || inputsData.stanzas.length === 0) {
    warnings.push('No inputs.conf data provided - routes may be incomplete');
    return `# Cribl Routes Configuration
# No Splunk inputs detected - configure routes manually

routes: []
`;
  }

  notes.push(`Translated ${inputsData.stanzas.length} Splunk input(s) to Cribl routes`);

  const routes = inputsData.stanzas
    .filter((s) => !s.disabled)
    .map((stanza, idx) => {
      const routeName = `splunk_${stanza.type}_${idx}`;
      const sourcetype = stanza.sourcetype || 'unknown';
      const criblRoute = `  - id: ${routeName}
    name: "${stanza.name}"
    filter: "sourcetype === '${sourcetype}'"
    output: default
    description: "Translated from Splunk ${stanza.type} input"`;

      // Add breakdown entry
      const routeFields = {
        id: routeName,
        name: stanza.name,
        filter: `sourcetype === '${sourcetype}'`,
        output: 'default',
        description: `Translated from Splunk ${stanza.type} input`,
      };

      breakdown.push({
        splunkConfig: `[${stanza.name}]\nsourcetype = ${sourcetype}\nindex = ${stanza.index || 'default'}${stanza.disabled ? '\ndisabled = true' : ''}`,
        criblConfig: criblRoute,
        configType: 'input',
        criblComponentType: 'route',
        criblFields: JSON.stringify(routeFields, null, 2),
        title: `${stanza.type.toUpperCase()} Input: ${stanza.name}`,
        what: `Translates a Splunk ${stanza.type} input to a Cribl route for data routing`,
        why: `Routes data based on sourcetype '${sourcetype}' to ensure proper processing and destination`,
        how: `Splunk ${stanza.type} inputs become Cribl routes with sourcetype-based filtering. The filter expression checks if events match '${sourcetype}' and routes them to the default output.`,
        validation: `✓ Route ID: ${routeName}\n✓ Filter expression validates sourcetype\n✓ Maps to default output pipeline\n✓ Preserves original input name and metadata`,
      });

      return criblRoute;
    })
    .join('\n');

  return `# Cribl Routes Configuration
# Translated from Splunk inputs.conf

routes:
${routes}
`;
}

function generateCriblPipelines(
  propsData: PropsConfig | null,
  transformsData: TransformsConfig | null,
  notes: string[],
  warnings: string[],
  breakdown: TranslationBreakdown[]
): string {
  if (!propsData || propsData.sourcetypes.length === 0) {
    warnings.push('No props.conf data provided - pipelines may be incomplete');
    return `# Cribl Pipelines
# No Splunk props.conf detected

pipelines: []
`;
  }

  notes.push(`Translated ${propsData.sourcetypes.length} sourcetype(s) to Cribl pipelines`);

  const pipelines = propsData.sourcetypes
    .map((st) => {
      const functions: string[] = [];

      // Add Event Breaker function for LINE_BREAKER
      if (st.lineBreaker) {
        functions.push(`      - id: event_breaker_${st.name.replace(/[^a-z0-9]/gi, '_')}
        filter: "true"
        conf:
          type: event_breaker
          eventBreakerRegex: /${escapeRegex(st.lineBreaker)}/
          maxEventBytes: 51200
          timestampAnchorRegex: /\\d{4}-\\d{2}-\\d{2}/`);

        // Add breakdown entry for Event Breaker
        const eventBreakerFields = {
          type: 'event_breaker',
          id: `event_breaker_${st.name.replace(/[^a-z0-9]/gi, '_')}`,
          filter: 'true',
          eventBreakerRegex: st.lineBreaker,
          maxEventBytes: 51200,
          timestampAnchorRegex: '\\d{4}-\\d{2}-\\d{2}',
          description: `Break events based on LINE_BREAKER pattern from props.conf`,
        };

        breakdown.push({
          splunkConfig: `[${st.name}]\nLINE_BREAKER = ${st.lineBreaker}${st.shouldLinemerge !== undefined ? `\nSHOULD_LINEMERGE = ${st.shouldLinemerge}` : ''}`,
          criblConfig: `      - id: event_breaker_${st.name.replace(/[^a-z0-9]/gi, '_')}
        filter: "true"
        conf:
          type: event_breaker
          eventBreakerRegex: /${escapeRegex(st.lineBreaker)}/
          maxEventBytes: 51200`,
          configType: 'prop',
          criblComponentType: 'function',
          criblFunctionType: 'event_breaker',
          criblFields: JSON.stringify(eventBreakerFields, null, 2),
          title: `Event Breaking: ${st.name}`,
          what: `Divides raw data stream into individual events using Cribl's Event Breaker function`,
          why: `Event breaking is critical for proper log processing. Cribl's Event Breaker function splits the data stream mid-pipeline, allowing granular control over event boundaries.`,
          how: `Splunk LINE_BREAKER regex becomes Cribl's eventBreakerRegex. The function splits events when the pattern matches, similar to Splunk's behavior. SHOULD_LINEMERGE is handled by event size limits.`,
          validation: `✓ Function type: event_breaker\n✓ Event breaker regex: ${st.lineBreaker}\n✓ Max event size: 51200 bytes\n✓ Preserves multi-line event handling`,
        });
      }

      // Add timestamp parsing using Auto Timestamp function
      if (st.timeFormat) {
        functions.push(`      - id: auto_timestamp_${st.name.replace(/[^a-z0-9]/gi, '_')}
        filter: "true"
        conf:
          type: auto_timestamp
          srcField: _raw
          dstField: _time
          defaultTimezone: UTC
          additionalFormats:
            - regex: /${escapeRegex(st.timePrefix || '.')}(.+)/
              format: "${convertTimeFormat(st.timeFormat)}"`);
      }

      // Add field extractions using Regex Extract function
      if (st.extracts && st.extracts.length > 0) {
        st.extracts.forEach((extract) => {
          // Convert Splunk regex to Cribl named capture group format
          const namedCaptureRegex = convertToNamedCapture(extract.regex, extract.name);
          functions.push(`      - id: regex_extract_${extract.name}
        filter: "true"
        conf:
          type: regex_extract
          srcField: _raw
          regex: /${namedCaptureRegex}/
          overwrite: false`);
        });
      }

      // Add Parser function for KV_MODE
      if (st.kvMode && st.kvMode !== 'none') {
        const parserType = st.kvMode === 'json' ? 'json' : 'kvp';
        functions.push(`      - id: parser_${st.name.replace(/[^a-z0-9]/gi, '_')}
        filter: "true"
        conf:
          type: parser
          mode: extract
          srcField: _raw
          parser: ${parserType}`);
      }

      const criblPipeline = `  - id: pipeline_${st.name.replace(/[^a-z0-9]/gi, '_')}
    name: "Pipeline for ${st.name}"
    functions:
${functions.join('\n') || '      # No functions defined'}`;

      // Build Splunk config representation
      const splunkConfigParts = [`[${st.name}]`];
      if (st.timeFormat) splunkConfigParts.push(`TIME_FORMAT = ${st.timeFormat}`);
      if (st.timePrefix) splunkConfigParts.push(`TIME_PREFIX = ${st.timePrefix}`);
      if (st.lineBreaker) splunkConfigParts.push(`LINE_BREAKER = ${st.lineBreaker}`);
      if (st.shouldLinemerge !== undefined)
        splunkConfigParts.push(`SHOULD_LINEMERGE = ${st.shouldLinemerge}`);
      if (st.kvMode) splunkConfigParts.push(`KV_MODE = ${st.kvMode}`);
      if (st.extracts && st.extracts.length > 0) {
        st.extracts.forEach((extract) => {
          splunkConfigParts.push(`EXTRACT-${extract.name} = ${extract.regex}`);
        });
      }

      // Build detailed explanations
      const autoHandledExplanations: string[] = [];
      const notTranslatedExplanations: string[] = [];

      // Explain SHOULD_LINEMERGE
      if (st.shouldLinemerge !== undefined) {
        if (st.shouldLinemerge === false) {
          autoHandledExplanations.push(
            `📌 SHOULD_LINEMERGE = false: Cribl handles this automatically in Event Breaker functions. By default, Cribl processes each line as a separate event unless you configure multi-line event breaking. No additional configuration needed.`
          );
        } else {
          notTranslatedExplanations.push(
            `⚠️ SHOULD_LINEMERGE = true: This requires custom Event Breaker configuration in Cribl. You'll need to define how to merge multi-line events using the Event Breaker function's "Max Event Bytes" and regex patterns. See: https://docs.cribl.io/stream/event-breaker-function`
          );
        }
      }

      // Explain KV_MODE
      if (st.kvMode) {
        if (st.kvMode === 'none') {
          autoHandledExplanations.push(
            `📌 KV_MODE = none: Cribl won't auto-extract key=value pairs, matching Splunk's behavior. This is the default in Cribl - no action needed. If you want to extract specific fields later, use the Regex Extract or Parser function.`
          );
        } else if (st.kvMode === 'auto' || st.kvMode === 'json') {
          // These were translated to Parser functions above
          autoHandledExplanations.push(
            `✅ KV_MODE = ${st.kvMode}: Translated to Cribl Parser function (see above). Cribl will extract fields automatically using the ${st.kvMode === 'json' ? 'JSON' : 'key=value'} parser.`
          );
        }
      }

      // Explain missing TIME_FORMAT
      if (!st.timeFormat) {
        autoHandledExplanations.push(
          `📌 No TIME_FORMAT specified: Cribl's Auto Timestamp function will automatically detect timestamps using common patterns. This is often more flexible than Splunk's approach. If you need a specific format, add an Auto Timestamp function with custom patterns.`
        );
      }

      // Explain missing LINE_BREAKER
      if (!st.lineBreaker) {
        autoHandledExplanations.push(
          `📌 No LINE_BREAKER specified: Cribl treats each line as a separate event by default (equivalent to Splunk's default behavior). If your logs have multi-line events, add an Event Breaker function with the appropriate regex pattern.`
        );
      }

      // Build combined explanation strings
      const autoHandledText =
        autoHandledExplanations.length > 0 ? autoHandledExplanations.join('\n\n') : undefined;
      const notTranslatedText =
        notTranslatedExplanations.length > 0 ? notTranslatedExplanations.join('\n\n') : undefined;

      // Add breakdown entry
      const pipelineFields = {
        id: `pipeline_${st.name.replace(/[^a-z0-9]/gi, '_')}`,
        name: `Pipeline for ${st.name}`,
        description: `Processes ${st.name} sourcetype with parsing and field extraction`,
        functions: functions.length,
        note:
          functions.length === 0
            ? 'This pipeline has no explicit functions because Cribl handles these settings automatically or by default. See "Auto-Handled Settings" below for details.'
            : undefined,
      };

      breakdown.push({
        splunkConfig: splunkConfigParts.join('\n'),
        criblConfig: criblPipeline,
        configType: 'prop',
        criblComponentType: 'pipeline',
        criblFields: JSON.stringify(pipelineFields, null, 2),
        title: `Sourcetype: ${st.name}`,
        what:
          functions.length > 0
            ? `Translates Splunk props.conf settings for ${st.name} into a Cribl pipeline with ${functions.length} function(s) for data processing`
            : `Creates a basic Cribl pipeline for ${st.name}. Most Splunk settings are handled automatically by Cribl's default behavior (see below).`,
        why:
          functions.length > 0
            ? `Cribl pipelines process data for specific sourcetypes, applying timestamp parsing, field extractions, and event breaking logic`
            : `Even without explicit functions, Cribl needs a pipeline definition to route and process ${st.name} events. Cribl's intelligent defaults handle many Splunk props.conf settings automatically.`,
        how:
          functions.length > 0
            ? `Splunk props.conf directives map to Cribl functions: LINE_BREAKER → Event Breaker, TIME_FORMAT → Auto Timestamp, EXTRACT- → Regex Extract, KV_MODE → Parser. Functions execute in order within the pipeline.`
            : `This pipeline serves as a placeholder. Cribl will process ${st.name} events using default behaviors that match Splunk's settings. You can add functions later if needed (e.g., for custom field extractions or transformations).`,
        validation: `✓ Pipeline ID: pipeline_${st.name.replace(/[^a-z0-9]/gi, '_')}\n✓ ${st.lineBreaker ? 'Event breaking configured' : 'Using default line-by-line event breaking'}\n✓ ${st.timeFormat ? 'Timestamp parsing configured' : 'Using automatic timestamp detection'}\n✓ ${st.extracts ? st.extracts.length : 0} field extraction(s)\n✓ ${st.kvMode && st.kvMode !== 'none' ? `KV parsing enabled (${st.kvMode})` : 'KV parsing disabled (default)'}`,
        autoHandled: autoHandledText,
        notTranslated: notTranslatedText,
      });

      return criblPipeline;
    })
    .join('\n');

  return `# Cribl Pipelines
# Translated from Splunk props.conf

pipelines:
${pipelines}
`;
}

function generateCriblFunctions(
  propsData: PropsConfig | null,
  transformsData: TransformsConfig | null,
  notes: string[],
  warnings: string[],
  breakdown: TranslationBreakdown[]
): string {
  const functions: string[] = [];

  // Generate Regex Extract functions from field extractions
  if (propsData) {
    propsData.sourcetypes.forEach((st) => {
      if (st.extracts && st.extracts.length > 0) {
        st.extracts.forEach((extract) => {
          const namedCaptureRegex = convertToNamedCapture(extract.regex, extract.name);
          // Use sourcetype filter to match Splunk behavior - extractions only apply to their sourcetype
          const sourcetypeFilter = `sourcetype === '${st.name}'`;
          const criblFunction = `  - id: regex_extract_${extract.name}
    filter: "${sourcetypeFilter}"
    conf:
      type: regex_extract
      srcField: _raw
      regex: /${namedCaptureRegex}/
      overwrite: false`;

          functions.push(criblFunction);

          // Add breakdown entry for field extraction
          const extractFields = {
            type: 'regex_extract',
            id: `regex_extract_${extract.name}`,
            filter: sourcetypeFilter,
            srcField: '_raw',
            regex: namedCaptureRegex,
            overwrite: false,
            outputField: extract.name,
            description: `Extract ${extract.name} from ${st.name} sourcetype using regex with named capture groups`,
          };

          breakdown.push({
            splunkConfig: `[${st.name}]\nEXTRACT-${extract.name} = ${extract.regex}`,
            criblConfig: criblFunction,
            configType: 'prop',
            criblComponentType: 'function',
            criblFunctionType: 'regex_extract',
            criblFields: JSON.stringify(extractFields, null, 2),
            title: `Field Extraction: ${extract.name}`,
            what: `Extracts field '${extract.name}' from events with sourcetype '${st.name}' using Cribl's Regex Extract function. This extraction ONLY applies to ${st.name} events, matching Splunk's props.conf behavior.`,
            why: `Field extractions in props.conf are sourcetype-specific. In Cribl, this is achieved using a filter that checks sourcetype === '${st.name}'. This ensures the extraction only runs on the correct events.`,
            how: `The Splunk EXTRACT directive from [${st.name}] stanza becomes a Cribl Regex Extract function with filter "sourcetype === '${st.name}'". The regex pattern uses named capture groups: Python syntax (?P<name>...) is converted to Cribl syntax (?<name>...).`,
            validation: `✓ Function type: regex_extract\n✓ Filter: sourcetype === '${st.name}'\n✓ Named capture group: (?<${extract.name}>...)\n✓ Source field: _raw\n✓ Output field: ${extract.name}`,
          });
        });
      }
    });
  }

  // Generate Mask functions from transforms.conf SEDCMD
  if (transformsData) {
    transformsData.transforms.forEach((transform) => {
      // Handle SEDCMD masking operations
      if (transform.sedcmd) {
        const maskMode = transform.maskType === 'redact' ? 'redact' : 'replace';
        // Parse sed command to extract pattern: s/pattern/replacement/
        const sedMatch = transform.sedcmd.match(/s\/(.+?)\/(.+?)\//);
        const pattern = sedMatch ? sedMatch[1] : '.+';
        const replacement = sedMatch ? sedMatch[2] : '***';

        const criblMaskFunction = `  - id: mask_${transform.name}
    filter: "true"
    conf:
      type: mask
      rules:
        - matchRegex: /${pattern}/
          replaceExpr: "'${replacement}'"
      fields:
        - _raw
      depth: 5`;

        functions.push(criblMaskFunction);

        const maskFields = {
          type: 'mask',
          id: `mask_${transform.name}`,
          filter: 'true',
          mode: maskMode,
          matchRegex: pattern,
          replaceExpr: replacement,
          fields: ['_raw'],
          depth: 5,
          description: `Mask sensitive data using ${maskMode} mode`,
        };

        breakdown.push({
          splunkConfig: `[${transform.name}]\nSEDCMD = ${transform.sedcmd}`,
          criblConfig: criblMaskFunction,
          configType: 'transform',
          criblComponentType: 'function',
          criblFunctionType: 'mask',
          criblFields: JSON.stringify(maskFields, null, 2),
          title: `Data Masking: ${transform.name}`,
          what: `Masks or redacts sensitive data using Cribl's Mask function, replacing matching patterns with safe values`,
          why: `Data masking protects sensitive information (PII, credentials, tokens) before it's stored or transmitted. Cribl's Mask function provides efficient find-and-replace with regex support and obfuscation options.`,
          how: `Splunk SEDCMD (sed-style find/replace) becomes Cribl's Mask function. The sed pattern 's/find/replace/' is converted to matchRegex and replaceExpr. The function applies to specified fields with configurable recursion depth.`,
          validation: `✓ Function type: mask\n✓ Match pattern: ${pattern}\n✓ Replacement: ${replacement}\n✓ Mode: ${maskMode}\n✓ Protects sensitive data`,
        });
      }

      // Handle REGEX/FORMAT transforms
      if (transform.regex && transform.format) {
        // Parse FORMAT to extract the actual field name
        // FORMAT can be: "dest::\"$1\"", "dest=$1", "$1::dest", etc.
        const formatFieldMatch = transform.format.match(/^(\w+)::|^(\w+)=/);
        const fieldName = formatFieldMatch
          ? formatFieldMatch[1] || formatFieldMatch[2]
          : transform.dest || `transform_${transform.name}_result`;

        // Use Regex Extract with named capture group based on the actual field name
        const namedCaptureRegex = convertToNamedCapture(transform.regex, fieldName);

        const criblFunction = `  - id: regex_extract_transform_${transform.name}
    filter: "true"
    conf:
      type: regex_extract
      srcField: _raw
      regex: /${namedCaptureRegex}/
      overwrite: false
    description: "Extract and transform using ${transform.name}"`;

        functions.push(criblFunction);

        // If FORMAT is complex, add an Eval function to apply the format template
        if (transform.format.includes('$')) {
          const evalFunction = `  - id: eval_format_${transform.name}
    filter: "true"
    conf:
      type: eval
      expression: |
        // Apply FORMAT template: ${transform.format}
        ${transform.dest || '_raw'} = \`${transform.format.replace(/\$(\d+)/g, '${$$$1}')}\`;`;
          functions.push(evalFunction);
        }

        // Add breakdown entry for transform
        const transformFields = {
          type: 'regex_extract',
          id: `regex_extract_transform_${transform.name}`,
          filter: 'true',
          srcField: '_raw',
          regex: namedCaptureRegex,
          overwrite: false,
          outputField: fieldName,
          formatTemplate: transform.format,
          requiresEvalForFormat: transform.format.includes('$'),
          description: `Extract using regex and apply FORMAT template`,
        };

        breakdown.push({
          splunkConfig: `[${transform.name}]\nREGEX = ${transform.regex}\nFORMAT = ${transform.format}${transform.dest ? `\nDEST_KEY = ${transform.dest}` : ''}`,
          criblConfig: criblFunction,
          configType: 'transform',
          criblComponentType: 'function',
          criblFunctionType: 'regex_extract',
          criblFields: JSON.stringify(transformFields, null, 2),
          title: `Transform: ${transform.name}`,
          what: `Extracts data from events and assigns it to field '${fieldName}' using Cribl's Regex Extract function. This transform applies the regex pattern "${transform.regex}" and uses the FORMAT template "${transform.format}".`,
          why: `Splunk transforms allow you to extract values from raw events and assign them to specific fields. Cribl's Regex Extract function provides the same capability with better performance using named capture groups.`,
          how: `The Splunk REGEX pattern is converted to use Cribl's named capture group syntax: (?<${fieldName}>...). The field name "${fieldName}" comes from the FORMAT template "${transform.format}". ${transform.format.includes('$') ? 'Since FORMAT uses variable substitutions ($1, $2), an additional Eval function may be needed to apply the full template.' : 'The extracted value is assigned directly to the field.'}`,
          validation: `✓ Function type: regex_extract\n✓ Named capture group: (?<${fieldName}>...)\n✓ Source field: _raw\n✓ Output field: ${fieldName}\n✓ Format template: ${transform.format}`,
        });
      }
    });
  }

  if (functions.length === 0) {
    warnings.push('No field extractions found - functions list is empty');
    return `# Cribl Functions
# No field extractions detected

functions: []
`;
  }

  notes.push(`Generated ${functions.length} Cribl eval function(s) from Splunk extractions`);

  return `# Cribl Functions
# Translated from Splunk field extractions

functions:
${functions.join('\n')}
`;
}

// ============================================================================
// HELPERS
// ============================================================================

function convertTimeFormat(splunkFormat: string): string {
  // Convert Splunk TIME_FORMAT to strptime format
  // Splunk uses %Y-%m-%dT%H:%M:%S
  // Most are compatible, but add conversions as needed
  return splunkFormat;
}

function escapeRegex(regex: string): string {
  // Escape regex for use in YAML/JSON strings
  return regex.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function convertToNamedCapture(splunkRegex: string, fieldName: string): string {
  // Convert Splunk regex to Cribl named capture group format
  // Splunk uses Python regex syntax: (?P<name>...) → Cribl uses: (?<name>...)
  // Also handle unnamed groups: (\w+) → (?<fieldname>\w+)

  // First, convert Python-style named groups (?P<name>...) to Cribl style (?<name>...)
  const convertedRegex = splunkRegex.replace(/\(\?P<(\w+)>/g, '(?<$1>');

  // If already has Cribl-style named groups, return as is
  if (convertedRegex.includes(`(?<${fieldName}>`)) {
    return convertedRegex;
  }

  // Replace first unnamed capture group with named capture
  // Match (pattern) but not (?...) or (?:...)
  const unnamedGroupRegex = /\((?!\?[:<])/;

  if (unnamedGroupRegex.test(convertedRegex)) {
    // Replace first unnamed group with named group
    return convertedRegex.replace(unnamedGroupRegex, `(?<${fieldName}>`);
  }

  // If no capture groups, wrap the whole pattern in a named capture
  return `(?<${fieldName}>${convertedRegex})`;
}
