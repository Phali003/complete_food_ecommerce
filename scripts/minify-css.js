const fs = require('fs').promises;
const postcss = require('postcss');
const cssnano = require('cssnano');

/**
 * Simple CSS validation to check for matching braces
 * @param {string} content CSS content to validate
 * @return {boolean} Whether the CSS is valid
 */
async function validateCSS(content) {
    // Remove comments for validation
    let tempContent = content.replace(/\/\*[\s\S]*?\*\//g, '');
    let stack = [];
    let valid = true;

    // Validate brace matching
    for (let char of tempContent) {
        if (char === '{') {
            stack.push(char);
        } else if (char === '}') {
            if (stack.length === 0) {
                valid = false;
                break;
            }
            stack.pop();
        }
    }

    return stack.length === 0 && valid;
}

async function minifyCSS() {
    const cssFiles = [
        'browseProduct/browseProduct.css',
        'public/css/aboutUs.css',
        'public/css/auth.css',
        'public/css/checkOut.css',
        'public/css/confirm.css',
        'public/css/homePage.css',
        'public/css/loginModal.css',
        'public/css/viewCart.css',
        'public/css/components/Login.css',
        'src/components/AdminSetup.css'
    ];

    // Configure PostCSS
    const postcssProcessor = postcss([
        cssnano({
            preset: ['default', {
                discardComments: {
                    removeAll: true,
                },
                normalizeWhitespace: true,
                minifyGradients: true,
                reduceIdents: false,
                zindex: false
            }]
        })
    ]);

    let successCount = 0;
    let errorCount = 0;
    let skippedCount = 0;

    for (const file of cssFiles) {
        try {
            console.log(`Processing ${file}...`);
            let content = await fs.readFile(file, 'utf8');
            
            // Skip empty files
            if (!content.trim()) {
                console.log(`⚠ ${file} is empty, skipping...`);
                skippedCount++;
                continue;
            }
            
            // Validate CSS before processing
            if (!await validateCSS(content)) {
                console.error(`× Validation error in ${file}:`);
                console.error(`  Please run 'npm run fix-css' first to fix syntax errors.`);
                errorCount++;
                continue;
            }
            
            // Process the CSS
            const result = await postcssProcessor.process(content, {
                from: file,
                to: file.replace('.css', '.min.css')
            });

            // Write the minified CSS
            await fs.writeFile(file.replace('.css', '.min.css'), result.css);
            
            // Log the compression ratio
            const originalSize = content.length;
            const minifiedSize = result.css.length;
            const ratio = ((1 - minifiedSize / originalSize) * 100).toFixed(2);
            
            console.log(`✓ ${file}`);
            console.log(`  Original size: ${originalSize} bytes`);
            console.log(`  Minified size: ${minifiedSize} bytes`);
            console.log(`  Saved: ${ratio}%\n`);
            
            successCount++;
        } catch (error) {
            console.error(`× Error processing ${file}:`);
            console.error(`  ${error.message}\n`);
            errorCount++;
        }
    }

    return { successCount, errorCount, skippedCount };
}

// Run the minification
console.log('Starting CSS minification...\n');
minifyCSS().then(({ successCount, errorCount, skippedCount }) => {
    console.log('CSS minification complete!');
    console.log(`Successfully minified: ${successCount} files`);
    if (errorCount > 0) {
        console.log(`Failed to minify: ${errorCount} files`);
        console.log(`Skipped: ${skippedCount} files`);
        console.log('\nPlease run "npm run fix-css" first to fix any CSS syntax errors.');
    }
}).catch(error => {
    console.error('Error during minification:', error);
    process.exit(1);
});

