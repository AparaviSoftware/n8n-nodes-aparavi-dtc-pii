# Aparavi PII Censor Node for n8n

A powerful n8n community node that provides flexible PII (Personally Identifiable Information) censoring using the Aparavi DTC (Data Transformation Cloud) service. This node can handle any type of input data and automatically detect and censor PII according to various compliance standards.

## Features

- **Flexible Input Handling**: Accepts any input from previous nodes (text, JSON, arrays, objects)
- **Auto-detection**: Automatically detects input type and processes accordingly
- **Multiple PII Types**: Supports USA PII, International PII, and Healthcare Data (HIPAA)
- **Field-specific Processing**: Process all fields or specific fields only
- **Test Mode**: Built-in test mode for development and validation
- **Preserve Structure**: Maintains original data structure while censoring PII
- **Batch Processing**: Efficiently processes arrays and collections
- **Error Handling**: Robust error handling with continue-on-fail support

## Installation

1. Install the package:
```bash
npm install n8n-nodes-aparavi-pii
```

2. Copy the node files to your n8n custom nodes directory:
```bash
cp -r dist/* /path/to/your/n8n/custom/nodes/
```

3. Restart n8n to load the new node.

## Configuration

### Credentials

You'll need to configure the Aparavi API credentials:

1. Go to n8n Settings > Credentials
2. Add new credential of type "Aparavi API"
3. Enter your Aparavi DTC API key

### Node Parameters

#### Operation
- **Censor PII**: Main operation to censor PII in input data
- **Test Mode**: Test the connection and show sample output

#### PII Type
- **USA PII**: Detects and censors USA-specific PII (SSN, driver license, etc.)
- **International PII**: Detects and censors international PII (passport, phone, etc.)
- **Healthcare Data (HIPAA)**: Detects and censors healthcare data under HIPAA regulations

#### Input Data
- **Auto-detect**: Automatically detects input type and processes accordingly
- **All Fields**: Process all fields in objects/arrays
- **Specific Fields**: Process only specified fields (comma-separated list)

#### Options
- **Preserve Structure**: Whether to preserve the original data structure
- **Include Metadata**: Whether to include PII detection metadata in the output
- **Batch Size**: Number of items to process in each batch (for arrays)

## Usage Examples

### Basic Text Censoring

```json
{
  "input": "John Smith, SSN: 123-45-6789, Phone: (555) 123-4567",
  "piiType": "usa",
  "operation": "censor"
}
```

### Object Processing

```json
{
  "input": {
    "name": "Jane Doe",
    "email": "jane.doe@example.com",
    "ssn": "987-65-4321",
    "phone": "(555) 987-6543"
  },
  "piiType": "usa",
  "operation": "censor",
  "inputData": "all"
}
```

### Specific Fields Only

```json
{
  "input": {
    "name": "John Smith",
    "email": "john@example.com",
    "ssn": "123-45-6789",
    "notes": "Some notes here"
  },
  "piiType": "usa",
  "operation": "censor",
  "inputData": "specific",
  "fieldsToProcess": "name,ssn"
}
```

### Array Processing

```json
{
  "input": [
    {
      "name": "John Smith",
      "ssn": "123-45-6789"
    },
    {
      "name": "Jane Doe",
      "ssn": "987-65-4321"
    }
  ],
  "piiType": "usa",
  "operation": "censor"
}
```

## Test Mode

The node includes a built-in test mode that allows you to:

1. Test the connection to Aparavi DTC
2. Try different PII types with sample data
3. Validate the node configuration
4. See sample outputs before processing real data

### Test Sample Data

- **USA PII Sample**: Contains SSN, driver license, phone, email, address
- **International PII Sample**: Contains passport, international phone, address
- **HIPAA Sample**: Contains patient data, medical records, SSN
- **Custom Sample**: Use your own test data

## Supported PII Types

### USA PII
- Social Security Numbers (SSN)
- Driver's License Numbers
- Phone Numbers
- Email Addresses
- Physical Addresses
- Credit Card Numbers
- Bank Account Numbers

### International PII
- Passport Numbers
- International Phone Numbers
- National ID Numbers
- International Addresses
- Various country-specific identifiers

### Healthcare Data (HIPAA)
- Patient Names
- Medical Record Numbers
- Health Insurance Numbers
- Medical Conditions
- Treatment Information
- Provider Information

## Error Handling

The node includes comprehensive error handling:

- **Connection Errors**: Handles API connection issues
- **Validation Errors**: Validates input data and parameters
- **Processing Errors**: Handles individual item processing failures
- **Continue on Fail**: Option to continue processing other items if one fails

## Development

### Building

```bash
npm run build
```

### Linting

```bash
npm run lint
```

### Formatting

```bash
npm run format
```

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:

1. Check the [Aparavi Documentation](https://docs.aparavi.com)
2. Open an issue in this repository
3. Contact the maintainer

## Changelog

### v1.0.0
- Initial release
- Support for USA PII, International PII, and HIPAA data
- Flexible input handling for any data type
- Test mode functionality
- Comprehensive error handling
