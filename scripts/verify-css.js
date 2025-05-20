const fs = require('fs').promises;
const postcss = require('postcss');
const cssnano = require('cssnano');

async function verifyAndOptimize() {
    const cssFiles = [
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

    // Enhanced optimization settings
    const postcssProcessor = postcss([
        cssnano({
            preset: ['default', {
                discardComments: {
                    removeAll: true,
                },
                normalizeWhitespace: true,
                minifyGradients: true,
                reduceIdents: false,
                zindex: false,
                colormin: true,
                convertValues: true,
                discardDuplicates: true,
                mergeLonghand: true,
                mergeRules: true,
                minifyParams: true,
                minifySelectors: true,
                normalizePositions: true,
                normalizeString: true,
                normalizeUrl: true,
                orderedValues: true,
                reduceTransforms: true
            }]
        })
    ]);

    let totalOriginalSize = 0;
    let totalMinifiedSize = 0;

    console.log('Verifying and optimizing minified CSS files...\n');

    for (const file of cssFiles) {
        try {
            // Read the minified file
            const content = await fs.readFile(file, 'utf8');
            
            if (!content.trim()) {
                console.log(`⚠ ${file} is empty!`);
                continue;
            }

            // Verify the file is valid CSS
            try {
                const result = await postcssProcessor.process(content, {
                    from: file,
                    to: file
                });

                // Additional optimization pass
                const finalResult = await postcssProcessor.process(result.css, {
                    from: file,
                    to: file
                });

                // Compare sizes
                const originalSize = content.length;
                const finalSize = finalResult.css.length;
                
                totalOriginalSize += originalSize;
                totalMinifiedSize += finalSize;

                // If we can optimize further, update the file
                if (finalSize < originalSize) {
                    await fs.writeFile(file, finalResult.css);
                    console.log(`✓ ${file}`);
                    console.log(`  Further optimized from ${originalSize} to ${finalSize} bytes`);
                    console.log(`  Additional ${((1 - finalSize / originalSize) * 100).toFixed(2)}% reduction\n`);
                } else {
                    console.log(`✓ ${file}`);
                    console.log(`  Already optimally minified (${originalSize} bytes)\n`);
                }
            } catch (error) {
                console.error(`× Error in ${file}:`);
                console.error(`  Invalid CSS syntax: ${error.message}\n`);
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.error(`× ${file} not found!\n`);
            } else {
                console.error(`× Error processing ${file}:`, error.message, '\n');
            }
        }
    }

    // Print summary
    console.log('Optimization Summary:');
    console.log(`Total original size: ${totalOriginalSize} bytes`);
    console.log(`Total final size: ${totalMinifiedSize} bytes`);
    console.log(`Overall savings: ${((1 - totalMinifiedSize / totalOriginalSize) * 100).toFixed(2)}%`);
}

verifyAndOptimize().catch(error => {
    console.error('Error during verification:', error);
    process.exit(1);
});

