import type { GeneratedConfig, OutputFormat } from '@/types/logonboard';
import JSZip from 'jszip';

// Exporter Service - Creates ZIP or TXT bundles

export async function exportAsZip(config: GeneratedConfig): Promise<Buffer> {
  const zip = new JSZip();

  // Add configuration files
  zip.file('inputs.conf', config.inputsConf);
  zip.file('props.conf', config.propsConf);
  zip.file('transforms.conf', config.transformsConf);
  zip.file('README_for_engineer.txt', config.readme);
  zip.file('metadata.json', JSON.stringify(config.metadata, null, 2));

  // Generate the zip buffer
  const buffer = await zip.generateAsync({
    type: 'nodebuffer',
    compression: 'DEFLATE',
    compressionOptions: { level: 9 },
  });

  return buffer;
}

export function exportAsTxt(config: GeneratedConfig): string {
  const lines: string[] = [
    '='.repeat(80),
    'LogOnboard-AI Configuration Bundle',
    '='.repeat(80),
    '',
    '## INPUTS.CONF',
    '-'.repeat(40),
    config.inputsConf,
    '',
    '## PROPS.CONF',
    '-'.repeat(40),
    config.propsConf,
    '',
    '## TRANSFORMS.CONF',
    '-'.repeat(40),
    config.transformsConf,
    '',
    '## README',
    '-'.repeat(40),
    config.readme,
    '',
    '## METADATA',
    '-'.repeat(40),
    JSON.stringify(config.metadata, null, 2),
    '',
    '='.repeat(80),
    'End of Configuration Bundle',
    '='.repeat(80),
  ];

  return lines.join('\n');
}

export async function exportConfig(
  config: GeneratedConfig,
  format: OutputFormat
): Promise<{ data: Buffer | string; filename: string; contentType: string }> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

  if (format === 'zip') {
    const data = await exportAsZip(config);
    return {
      data,
      filename: `logonboard-config-${timestamp}.zip`,
      contentType: 'application/zip',
    };
  } else {
    const data = exportAsTxt(config);
    return {
      data,
      filename: `logonboard-config-${timestamp}.txt`,
      contentType: 'text/plain',
    };
  }
}
