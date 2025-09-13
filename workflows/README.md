# Aparavi PII Censor Workflows

This directory contains ready-to-use n8n workflows that demonstrate the Aparavi PII Censor node in action.

## Prerequisites

Before using these workflows, you must:

1. **Install the Aparavi PII Censor node**:
   - Go to Settings → Community Nodes in n8n
   - Search for `n8n-nodes-aparavi-dtc-pii`
   - Install the package

2. **Set up Aparavi API credentials**:
   - Create an Aparavi API account
   - Add your API key in n8n Credentials

## Available Workflows

### 1. Email PII Scrubber (`email-pii-scrubber.json`)
- **Purpose**: Process incoming emails and censor PII before forwarding
- **Use Case**: Internal email processing, support ticket handling
- **Input**: Gmail/IMAP email
- **Output**: Clean email to Slack or another destination

### 2. Database Export Sanitizer (`database-sanitizer.json`)
- **Purpose**: Export data from databases and sanitize PII
- **Use Case**: Data sharing, analytics, compliance
- **Input**: Database query results
- **Output**: Clean data to Google Sheets or file

### 3. Customer Data Processor (`customer-data-processor.json`)
- **Purpose**: Process customer data and anonymize PII
- **Use Case**: GDPR compliance, data sharing with partners
- **Input**: Customer records via webhook
- **Output**: Anonymized data to storage

## How to Use

1. **Download** the workflow JSON file you want to use
2. **Import** it into your n8n instance (Settings → Import)
3. **Configure** the nodes with your specific settings
4. **Test** with the provided sample data
5. **Activate** the workflow

## Sample Data

Check the `examples/sample-data/` directory for test data that works with these workflows.

## Support

- GitHub Issues: [Report problems or request new workflows](https://github.com/AparaviSoftware/n8n-nodes-aparavi-dtc-pii/issues)
- Documentation: [Full setup guide](https://github.com/AparaviSoftware/n8n-nodes-aparavi-dtc-pii#readme)
