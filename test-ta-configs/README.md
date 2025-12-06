# Test Splunk TA Configurations

These sample configuration files are used to test the **LogOnboard-AI TA Translator** feature.

## Files

### inputs.conf

- Monitor inputs for Apache access and error logs
- Script input for custom metrics
- TCP syslog input on port 9514

### props.conf

- Apache access log parsing (timestamp, field extractions)
- Apache error log parsing
- Custom metrics JSON handling

### transforms.conf

- User agent extraction
- HTTP method extraction
- URI extraction

## How to Test

1. Navigate to http://localhost:3000/ta-translator
2. Upload each config file to its respective section
3. Click "Translate to Cribl"
4. Review the generated Cribl Stream configurations
5. Download the complete configuration package

## Expected Output

The translator should generate:

- **Routes**: 4 routes (3 monitor inputs + 1 tcp input)
- **Pipelines**: 3 pipelines (one per sourcetype)
- **Functions**: Multiple eval functions for field extractions

All configurations should be in valid YAML format for Cribl Stream.
