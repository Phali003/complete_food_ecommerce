const fs = require('fs').promises;
const prettier = require('prettier');
const path = require('path');

async function addImportantComments(content, filename) {
    // Define essential comments based on file type
    const commonComments = {
        'variables': '/* CSS Variables - Theme colors and global settings */',
        'reset': '/* Base reset and default styles */',
        'layout': '/* Layout and structure styles */',
        'responsive': '/* Responsive design breakpoints */',
        'animations': '/* Animation keyframes and transitions */',
        'components': '/* Component-specific styles */'
    };

    // File-specific comments
    const fileComments = {
        'homePage': {
            header: '/* Homepage styles - Main layout and hero section */',
            featured: '/* Featured products grid and cards */',
            categories: '/* Category navigation and filters */'
        },
        'auth': {
            forms: '/* Authentication forms - Login and Register */',
            validation: '/* Form validation styles and states */',
            alerts: '/* Alert and notification styles */'
        },
        'checkOut': {
            process: '/* Checkout process steps and progress */',
            forms: '/* Payment and shipping forms */',
            summary: '/* Order summary and totals */'
        },
        'viewCart': {
            cart: '/* Shopping cart layout and items */',
            summary: '/* Cart summary and totals */',
            actions: '/* Cart action buttons and controls */'
        }
    };

    // Get base filename without extension
    const baseFile = path.basename(filename, '.formatted.css');
    const fileType = baseFile.replace('.min', '');

    // Add file-specific header comment
    let newContent = `/* ${fileType} styles - Main stylesheet */\n\n`;

    // Add relevant common comments where patterns are found
    if (content.includes(':root') || content.includes('var(--')) {
        newContent += commonComments.variables + '\n';
    }
    if (content.includes('margin: 0') || content.includes('padding: 0')) {
        newContent += commonComments.reset + '\n';
    }
    if (content.includes('@media')) {
        newContent += commonComments.responsive + '\n';
    }
    if (content.includes('@keyframes') || content.includes('transition')) {
        newContent += commonComments.animations + '\n';
    }

    // Add file-specific comments
    if (fileComments[fileType]) {
        Object.values(fileComments[fileType]).forEach(comment => {
            newContent += comment + '\n';
        });
    }

    // Add content after comments
    newContent += content;

    return newContent;
}

async function formatCSS() {
    const minifiedFiles = [
        'public/css/aboutUs.min.css',
        'public/css/auth.min.css',
        'public/css/checkOut.min.css',
        'public/css/confirm.min.css',
        'public/css/homePage.min.css',
        'public/css/loginModal.min.css',
        'public/css/viewCart.min.css',
        'public/css/components/Login.min.css',
        'src/components/AdminSetup.min.css'
    ];

    const prettierConfig = {
        parser: 'css',
        tabWidth: 2,
        useTabs: false,
        semi: true,
        singleQuote: false,
        printWidth: 80,
        bracketSpacing: true
    };

    console.log('Formatting CSS files and adding important comments...\n');

    for (const file of minifiedFiles) {
        try {
            console.log(`Processing ${file}...`);
            
            const content = await fs.readFile(file, 'utf8');
            let formattedContent = await prettier.format(content, prettierConfig);
            
            // Add important comments
            formattedContent = await addImportantComments(formattedContent, file);
            
            const formattedPath = file.replace('.min.css', '.formatted.css');
            await fs.writeFile(formattedPath, formattedContent);
            
            const originalSize = content.length;
            const formattedSize = formattedContent.length;
            
            console.log(`✓ Created formatted version with comments: ${formattedPath}`);
            console.log(`  Original size: ${originalSize} bytes`);
            console.log(`  Formatted size: ${formattedSize} bytes\n`);
            
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`⚠ ${file} not found, skipping...`);
            } else {
                console.error(`× Error processing ${file}:`, error.message);
            }
        }
    }
}

// Add the script to package.json
const addScriptToPackageJson = async () => {
    const packageJsonPath = path.join(process.cwd(), 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    if (!packageJson.scripts['format-css']) {
        packageJson.scripts['format-css'] = 'node scripts/format-css.js';
        await fs.writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n');
        console.log('Added format-css script to package.json');
    }
};

console.log('Starting CSS formatting with comments...\n');
Promise.all([formatCSS(), addScriptToPackageJson()])
    .then(() => {
        console.log('CSS formatting and commenting complete!');
        console.log('Formatted versions have been created with essential comments.');
        console.log('Original minified files remain unchanged for production use.');
    })
    .catch(error => {
        console.error('Error during formatting:', error);
        process.exit(1);
    });

