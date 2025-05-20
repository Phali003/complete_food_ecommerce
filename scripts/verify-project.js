const fs = require('fs').promises;
const path = require('path');

async function verifyProject() {
    // HTML files to check
    const htmlFiles = [
        'public/index.html',
        'public/reset-password.html',
        'public/aboutUs/aboutUs.html',
        'public/checkOut/checkOut.html',
        'public/confirmation/confirm.html',
        'public/viewCart/viewCart.html'
    ];

    // Expected minified CSS files
    const minifiedCssFiles = [
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

    console.log('Starting project verification...\n');
    
    // Check HTML files
    console.log('Checking HTML files for correct CSS references:');
    for (const file of htmlFiles) {
        try {
            const content = await fs.readFile(file, 'utf8');
            
            // Check for any non-minified CSS references
            const nonMinifiedRefs = content.match(/href=["'][^"']*?(?<!\.min)\.css["']/g);
            const minifiedRefs = content.match(/href=["'][^"']*?\.min\.css["']/g);
            
            console.log(`\n${file}:`);
            if (nonMinifiedRefs) {
                console.log('× Found non-minified CSS references:');
                nonMinifiedRefs.forEach(ref => console.log(`  ${ref}`));
            } else {
                console.log('✓ No non-minified CSS references found');
            }
            
            if (minifiedRefs) {
                console.log('✓ Found minified CSS references:');
                minifiedRefs.forEach(ref => console.log(`  ${ref}`));
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`⚠ ${file} not found`);
            } else {
                console.error(`× Error checking ${file}:`, error.message);
            }
        }
    }

    // Check minified CSS files
    console.log('\nVerifying minified CSS files:');
    for (const file of minifiedCssFiles) {
        try {
            const stats = await fs.stat(file);
            const content = await fs.readFile(file, 'utf8');
            
            console.log(`\n${file}:`);
            console.log(`✓ File exists (${stats.size} bytes)`);
            
            // Basic CSS validation
            if (content.includes('{') && content.includes('}')) {
                console.log('✓ Contains valid CSS syntax');
            } else {
                console.log('× May have invalid CSS syntax');
            }
            
            // Check for common minification indicators
            if (content.includes('\n\n') || content.includes('  ')) {
                console.log('⚠ May not be properly minified (contains extra whitespace)');
            } else {
                console.log('✓ Appears to be properly minified');
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`× ${file} not found!`);
            } else {
                console.error(`× Error checking ${file}:`, error.message);
            }
        }
    }

    console.log('\nVerification complete!');
}

verifyProject().catch(error => {
    console.error('Error during verification:', error);
    process.exit(1);
});

