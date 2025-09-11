# Installation Guide for Aparavi PII Censor Node

## Method 1: Install as npm package (Recommended)

1. **Install the package globally:**
   ```bash
   npm install -g /path/to/your/n8n-pii-node
   ```

2. **Or install locally in your n8n project:**
   ```bash
   cd /path/to/your/n8n/project
   npm install /path/to/your/n8n-pii-node
   ```

3. **Restart n8n:**
   ```bash
   n8n start
   ```

## Method 2: Copy to n8n custom nodes directory

1. **Find your n8n custom nodes directory:**
   - Default location: `~/.n8n/custom/`
   - Or check your n8n configuration

2. **Copy the dist folder:**
   ```bash
   cp -r /path/to/n8n-pii-node/dist /path/to/n8n/custom/nodes/n8n-nodes-aparavi-pii
   ```

3. **Install dependencies:**
   ```bash
   cd /path/to/n8n/custom/nodes/n8n-nodes-aparavi-pii
   npm install
   ```

4. **Restart n8n:**
   ```bash
   n8n start
   ```

## Method 3: Development mode (for testing)

1. **Link the package:**
   ```bash
   cd /path/to/n8n-pii-node
   npm link
   ```

2. **Link in n8n:**
   ```bash
   cd /path/to/your/n8n/project
   npm link n8n-nodes-aparavi-pii
   ```

3. **Restart n8n:**
   ```bash
   n8n start
   ```

## Troubleshooting

### Node doesn't appear in n8n

1. **Check n8n logs for errors:**
   ```bash
   n8n start --log-level debug
   ```

2. **Verify the node is properly built:**
   ```bash
   cd /path/to/n8n-pii-node
   npm run build
   ```

3. **Check if the node loads:**
   ```bash
   cd dist
   node -e "const pkg = require('./index.js'); console.log('Nodes:', Object.keys(pkg.nodes));"
   ```

4. **Verify n8n can find the node:**
   - Check that the package.json has the correct `n8n` configuration
   - Ensure the file paths in the `n8n` section are correct
   - Make sure all dependencies are installed

### Common Issues

1. **"Module not found" errors:**
   - Make sure all dependencies are installed
   - Check that the Aparavi library path is correct

2. **Node appears but doesn't work:**
   - Check the n8n logs for runtime errors
   - Verify your Aparavi API credentials are correct

3. **TypeScript compilation errors:**
   - Run `npm run build` to see detailed error messages
   - Fix any TypeScript errors before using the node

## Verification

After installation, you should see:
- "Aparavi PII Censor" in the node list
- "Aparavi API" in the credentials list
- The node should be in the "Transform" category

## Support

If you're still having issues:
1. Check the n8n documentation for custom nodes
2. Look at the n8n logs for specific error messages
3. Verify your n8n version is compatible
4. Make sure all dependencies are properly installed
