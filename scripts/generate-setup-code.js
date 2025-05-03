#!/usr/bin/env node

/**
 * Admin Setup Code Generator for Food E-commerce Platform
 * 
 * This script generates a secure code that will be used for the initial admin setup process.
 * The code should be set as the INITIAL_ADMIN_SETUP_CODE environment variable when deploying.
 * 
 * Usage:
 *   npm run setup-code
 * 
 * Options:
 *   --format=readable|base64|hex  Output format (default: readable)
 *   --length=NUMBER               Code length (default: 24 for readable, 32 for others)
 *   --no-separators               Disable separators for readable format
 *   --help                        Show this help message
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Default options
const DEFAULT_OPTIONS = {
  format: 'readable',
  length: {
    readable: 24,
    base64: 32,
    hex: 32
  },
  useSeparators: true,
  separator: '-',
  blockSize: 4
};

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    format: DEFAULT_OPTIONS.format,
    length: null,
    useSeparators: DEFAULT_OPTIONS.useSeparators,
    showHelp: false
  };

  args.forEach(arg => {
    if (arg.startsWith('--format=')) {
      options.format = arg.split('=')[1];
    } else if (arg.startsWith('--length=')) {
      options.length = parseInt(arg.split('=')[1], 10);
    } else if (arg === '--no-separators') {
      options.useSeparators = false;
    } else if (arg === '--help' || arg === '-h') {
      options.showHelp = true;
    }
  });

  // Set default length if not specified
  if (!options.length) {
    options.length = DEFAULT_OPTIONS.length[options.format] || 
                    DEFAULT_OPTIONS.length.readable;
  }

  return options;
}

// Show help message
function showHelp() {
  console.log(`
Admin Setup Code Generator for Food E-commerce Platform

This script generates a secure code that will be used for the initial admin setup process.
The code should be set as the INITIAL_ADMIN_SETUP_CODE environment variable when deploying.

Usage:
  npm run setup-code [options]

Options:
  --format=readable|base64|hex  Output format (default: readable)
  --length=NUMBER               Code length (default: depends on format)
  --no-separators               Disable separators for readable format
  --help                        Show this help message

Examples:
  npm run setup-code                         Generate readable code with default settings
  npm run setup-code -- --format=base64      Generate a base64 encoded code
  npm run setup-code -- --length=32          Generate a longer code
  npm run setup-code -- --no-separators      Generate code without separators
  `);
}

// Generate secure random bytes
function generateSecureBytes(numBytes) {
  try {
    return crypto.randomBytes(numBytes);
  } catch (error) {
    console.error('Error generating secure random bytes:', error.message);
    process.exit(1);
  }
}

// Generate a readable code (alphanumeric without ambiguous characters)
function generateReadableCode(length, useSeparators) {
  // Exclude ambiguous characters like 0O1lI
  const allowedChars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  
  // Generate more bytes than needed to ensure we can filter
  const bytesNeeded = Math.ceil(length * 1.5);
  const randomBytes = generateSecureBytes(bytesNeeded);
  
  // Convert bytes to readable characters
  let code = '';
  for (let i = 0; i < randomBytes.length && code.length < length; i++) {
    const index = randomBytes[i] % allowedChars.length;
    code += allowedChars[index];
  }
  
  // Ensure we have exact length
  code = code.substring(0, length);
  
  // Add separators if needed
  if (useSeparators && length >= DEFAULT_OPTIONS.blockSize) {
    const blockSize = DEFAULT_OPTIONS.blockSize;
    let formattedCode = '';
    
    for (let i = 0; i < code.length; i++) {
      if (i > 0 && i % blockSize === 0) {
        formattedCode += DEFAULT_OPTIONS.separator;
      }
      formattedCode += code[i];
    }
    
    return formattedCode;
  }
  
  return code;
}

// Generate a base64 code
function generateBase64Code(length) {
  // Calculate bytes needed (3 bytes = 4 base64 chars)
  const bytesNeeded = Math.ceil(length * 0.75);
  const randomBytes = generateSecureBytes(bytesNeeded);
  
  // Convert to base64 and trim to exact length
  let code = randomBytes.toString('base64');
  return code.substring(0, length);
}

// Generate a hex code
function generateHexCode(length) {
  // Calculate bytes needed (1 byte = 2 hex chars)
  const bytesNeeded = Math.ceil(length / 2);
  const randomBytes = generateSecureBytes(bytesNeeded);
  
  // Convert to hex and trim to exact length
  let code = randomBytes.toString('hex');
  return code.substring(0, length);
}

// Save the code to a temporary file
function saveCodeToFile(code) {
  try {
    const tempDir = path.join(__dirname, '..', 'temp');
    
    // Create temp directory if it doesn't exist
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const filePath = path.join(tempDir, 'setup-code.txt');
    fs.writeFileSync(filePath, `INITIAL_ADMIN_SETUP_CODE=${code}\n`, 'utf8');
    
    return filePath;
  } catch (error) {
    console.warn('Warning: Unable to save code to file:', error.message);
    return null;
  }
}

// Main function
function main() {
  // Parse command line arguments
  const options = parseArgs();
  
  // Show help if requested
  if (options.showHelp) {
    showHelp();
    return;
  }
  
  // Generate code based on format
  let code;
  try {
    switch (options.format) {
      case 'base64':
        code = generateBase64Code(options.length);
        break;
      case 'hex':
        code = generateHexCode(options.length);
        break;
      case 'readable':
      default:
        code = generateReadableCode(options.length, options.useSeparators);
        break;
    }
    
    // Display the generated code
    console.log('\n=================================================');
    console.log('           ADMIN SETUP CODE GENERATOR');
    console.log('=================================================\n');
    console.log(`Format: ${options.format.toUpperCase()}`);
    console.log(`Length: ${options.length} characters\n`);
    console.log('Your setup code:');
    console.log('----------------');
    console.log(code);
    console.log('\n=================================================');
    
    // Save to file
    const filePath = saveCodeToFile(code);
    if (filePath) {
      console.log(`Code also saved to: ${filePath}`);
    }
    
    console.log('\nInstructions:');
    console.log('1. Add this code to your .env file or environment variables:');
    console.log(`   INITIAL_ADMIN_SETUP_CODE=${code}`);
    console.log('2. Share this code securely with the person who will set up');
    console.log('   the initial admin account');
    console.log('3. After admin setup is complete, consider changing this code');
    console.log('=================================================\n');
    
  } catch (error) {
    console.error('Error generating setup code:', error.message);
    process.exit(1);
  }
}

// Execute main function
main();

