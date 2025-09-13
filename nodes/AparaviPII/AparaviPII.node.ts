import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

const AparaviDTC = require('../../aparavi-universal-pii.js');

export class AparaviPII implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Aparavi PII Censor',
		name: 'aparaviPII',
		// icon: 'aparavi.svg', // TODO: Fix icon display in n8n
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["piiType"]}}',
		description: 'Censor PII using Aparavi DTC with flexible input handling',
		defaults: {
			name: 'Aparavi PII Censor',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		credentials: [
			{
				name: 'aparaviApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'PII Type',
				name: 'piiType',
				type: 'options',
				options: [
					{
						name: 'USA PII',
						value: 'usa',
						description: 'Detect and censor USA-specific PII (SSN, driver license, etc.)',
					},
					{
						name: 'International PII',
						value: 'international',
						description: 'Detect and censor international PII (passport, phone, etc.)',
					},
					{
						name: 'Healthcare Data (HIPAA)',
						value: 'hipaa',
						description: 'Detect and censor healthcare data under HIPAA regulations',
					},
				],
				default: 'usa',
			},
			{
				displayName: 'Input Data',
				name: 'inputData',
				type: 'options',
				options: [
					{
						name: 'Auto-detect',
						value: 'auto',
						description: 'Automatically detect input type and process accordingly',
					},
					{
						name: 'All Fields',
						value: 'all',
						description: 'Process all fields in objects/arrays',
					},
					{
						name: 'Specific Fields',
						value: 'specific',
						description: 'Process only specified fields',
					},
				],
				default: 'auto',
			},
			{
				displayName: 'Fields to Process',
				name: 'fieldsToProcess',
				type: 'string',
				displayOptions: {
					show: {
						inputData: ['specific'],
					},
				},
				default: '',
				placeholder: 'e.g., name,email,phone,address',
				description: 'Comma-separated list of field names to process. Leave empty to process all fields.',
			},
			{
				displayName: 'Censor Character',
				name: 'censorChar',
				type: 'string',
				default: '█',
				description: 'Character to use for censoring PII',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Preserve Structure',
						name: 'preserveStructure',
						type: 'boolean',
						default: true,
						description: 'Whether to preserve the original data structure',
					},
					{
						displayName: 'Include Metadata',
						name: 'includeMetadata',
						type: 'boolean',
						default: false,
						description: 'Whether to include PII detection metadata in the output',
					},
					{
						displayName: 'Batch Size',
						name: 'batchSize',
						type: 'number',
						default: 10,
						description: 'Number of items to process in each batch (for arrays)',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		// Get credentials
		const credentials = await this.getCredentials('aparaviApi');
		if (!credentials?.apiKey) {
			throw new NodeOperationError(this.getNode(), 'Aparavi API credentials are required');
		}

		// Initialize Aparavi DTC client
		const aparavi = new AparaviDTC(credentials.apiKey as string);

		// Get parameters
		const piiType = this.getNodeParameter('piiType', 0) as string;
		const inputDataMode = this.getNodeParameter('inputData', 0) as string;
		const fieldsToProcess = inputDataMode === 'specific' ? this.getNodeParameter('fieldsToProcess', 0) as string : '';
		const options = this.getNodeParameter('options', 0) as any;

		for (let i = 0; i < items.length; i++) {
			try {
				let inputData = items[i].json;

				// Handle specific fields processing
				if (inputDataMode === 'specific' && fieldsToProcess) {
					const fields = fieldsToProcess.split(',').map(f => f.trim());
					const filteredData: any = {};
					
					if (typeof inputData === 'object' && inputData !== null) {
						fields.forEach(field => {
							if (field in inputData) {
								filteredData[field] = inputData[field];
							}
						});
					}
					
					inputData = filteredData;
				}

				// Process the data based on PII type
				let result: any;
				switch (piiType) {
					case 'usa':
						result = await aparavi.censorUSAPII(inputData);
						break;
					case 'international':
						result = await aparavi.censorInternationalPII(inputData);
						break;
					case 'hipaa':
						result = await aparavi.censorHIPAAData(inputData);
						break;
					default:
						throw new NodeOperationError(this.getNode(), `Unknown PII type: ${piiType}`);
				}

				// Prepare output data
				const outputData: any = {
					...items[i].json,
				};

				if (options.preserveStructure) {
					// Replace the original data with censored data
					outputData.censored = result;
				} else {
					// Replace the original data with censored data
					Object.assign(outputData, result);
				}

				if (options.includeMetadata) {
					outputData._metadata = {
						piiType: piiType,
						processedAt: new Date().toISOString(),
						originalKeys: Object.keys(items[i].json),
					};
				}

				returnData.push({
					json: outputData,
					pairedItem: { item: i },
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error instanceof Error ? error.message : String(error),
							original: items[i].json,
						},
						pairedItem: { item: i },
					});
				} else {
					throw new NodeOperationError(this.getNode(), `Failed to process item ${i}: ${error instanceof Error ? error.message : String(error)}`);
				}
			}
		}

		return [returnData];
	}
}
