# Aparavi PII & HIPAA Censor Node for n8n

A powerful n8n community node that provides flexible PII (Personally Identifiable Information) and HIPAA healthcare data censoring using the Aparavi DTC (Data Transformation Cloud) service. This node can handle any type of input data and automatically detect and censor PII and healthcare data according to various compliance standards including GDPR, HIPAA, and other privacy regulations.

## Features

- **PII & HIPAA Censoring**: Detects and censors both personally identifiable information and healthcare data
- **Compliance Ready**: Supports GDPR, HIPAA, and other privacy regulations
- **Flexible Input Handling**: Accepts any input from previous nodes (text, JSON, arrays, objects)
- **Auto-detection**: Automatically detects input type and processes accordingly
- **Multiple Data Types**: Supports USA PII, International PII, and Healthcare Data (HIPAA)
- **Field-specific Processing**: Process all fields or specific fields only
- **Preserve Structure**: Maintains original data structure while censoring sensitive data
- **Batch Processing**: Efficiently processes arrays and collections
- **Error Handling**: Robust error handling with continue-on-fail support

## Installation

### Community Nodes Installation

1. Open n8n and go to **Settings** → **Community Nodes**
2. Click **Install a community node**
3. Enter the package name: `n8n-nodes-aparavi-dtc-pii`
4. Click **Install**
5. The node will be automatically available in the Transform category

### Package Information

- **npm Package**: [n8n-nodes-aparavi-dtc-pii](https://www.npmjs.com/package/n8n-nodes-aparavi-dtc-pii)
- **GitHub Repository**: [AparaviSoftware/n8n-nodes-aparavi-dtc-pii](https://github.com/AparaviSoftware/n8n-nodes-aparavi-dtc-pii)

## Configuration

### Getting an Aparavi API Key

Before using this node, you'll need to sign up for an Aparavi DTC API key:

1. **Visit the Aparavi DTC Usage page**: [https://dtc.aparavi.com/usage](https://dtc.aparavi.com/usage)
2. **Sign up for an account** or log in if you already have one
3. **Generate an API key** from your dashboard
4. **Copy the API key** for use in n8n

### Setting up Credentials in n8n

1. Go to n8n Settings > Credentials
2. Add new credential of type "Aparavi API"
3. Enter your Aparavi DTC API key from the signup process above
4. Test the connection to ensure it's working

### Node Parameters

#### PII Type
- **USA PII**: Detects and censors USA-specific PII (SSN, driver license, etc.)
- **International PII**: Detects and censors international PII (passport, phone, etc.)
- **Healthcare Data (HIPAA)**: Detects and censors healthcare data under HIPAA regulations

#### Input Data Mode
- **All Fields**: Process all fields in objects/arrays
- **Specific Fields**: Process only specified fields (comma-separated list)

#### Fields to Process
- **Comma-separated list**: Specify which fields to process when using "Specific Fields" mode
- **Example**: `name,email,phone,ssn,address`

## Usage Examples

### Basic Text Censoring

```json
{
  "input": "John Smith, SSN: 123-45-6789, Phone: (555) 123-4567",
  "piiType": "usa"
}
```

### Object Processing (All Fields)

```json
{
  "input": {
    "name": "Jane Doe",
    "email": "jane.doe@example.com",
    "ssn": "987-65-4321",
    "phone": "(555) 987-6543"
  },
  "piiType": "usa",
  "inputDataMode": "all"
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
  "inputDataMode": "specific",
  "fieldsToProcess": "name,ssn"
}
```

### HIPAA Healthcare Data

```json
{
  "input": {
    "patientName": "Alice Williams",
    "ssn": "111-22-3333",
    "medicalRecord": "Patient has hypertension",
    "insuranceNumber": "BC123456789"
  },
  "piiType": "hipaa"
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
  "piiType": "usa"
}
```

## Supported Data Types

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
- Patient Names and Identifiers
- Medical Record Numbers
- Health Insurance Numbers
- Medical Conditions and Diagnoses
- Treatment Information
- Provider Information
- Prescription Information
- Medical Device Serial Numbers

## Error Handling

The node includes comprehensive error handling:

- **Connection Errors**: Handles API connection issues
- **Validation Errors**: Validates input data and parameters
- **Processing Errors**: Handles individual item processing failures
- **Continue on Fail**: Option to continue processing other items if one fails

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:

1. **Aparavi DTC Documentation**: [https://dtc.aparavi.com/usage](https://dtc.aparavi.com/usage)
2. **GitHub Issues**: [Report problems or request features](https://github.com/AparaviSoftware/n8n-nodes-aparavi-dtc-pii/issues)
3. **n8n Community**: [n8n Community Forum](https://community.n8n.io/)

## Changelog

### v1.1.1
- Enhanced PII and HIPAA data detection
- Improved error handling and validation
- Streamlined configuration options
- Updated documentation and examples

### v1.0.0
- Initial release
- Support for USA PII, International PII, and HIPAA data
- Flexible input handling for any data type
- Comprehensive error handling
