const fs = require('fs').promises;
const path = require('path');

async function updateReferences() {
    // HTML files to update
    const htmlFiles = [
        'public/index.html',
        'public/reset-password.html',
        'public/forgot-password.html',
        'public/aboutUs/aboutUs.html',
        'public/checkOut/checkOut.html',
        'public/confirmation/confirm.html',
        'public/viewCart/viewCart.html'
    ];

    // CSS files to remove after updating references
    const cssToRemove = [
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

    console.log('Updating HTML files to reference formatted CSS...\n');

    // First update HTML files
    for (const file of htmlFiles) {
        try {
            console.log(`Processing ${file}...`);
            let content = await fs.readFile(file, 'utf8');
            
            // Create backup
            await fs.writeFile(`${file}.backup`, content);
            
            // Replace .min.css with .formatted.css in all local CSS references
            // but preserve external CDN references
            content = content.replace(
                /href=["'](?!https?:\/\/)([^"']+)\.min\.css["']/g,
                (match, p1) => `href="${p1}.formatted.css"`
            );
            
            await fs.writeFile(file, content);
            console.log(`✓ Updated CSS references in ${file}`);
            console.log(`  Created backup: ${file}.backup\n`);
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`⚠ ${file} not found, skipping...\n`);
            } else {
                console.error(`× Error processing ${file}:`, error.message, '\n');
            }
        }
    }

    console.log('Removing minified CSS files...\n');

    // Then remove minified CSS files
    for (const file of cssToRemove) {
        try {
            await fs.unlink(file);
            console.log(`✓ Removed ${file}`);
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`⚠ ${file} already removed`);
            } else {
                console.error(`× Error removing ${file}:`, error.message);
            }
        }
    }

    console.log('\nSummary:');
    console.log('1. Updated HTML files to reference formatted CSS');
    console.log('2. Created backups of HTML files');
    console.log('3. Removed minified CSS files');
    console.log('\nProject now uses formatted CSS files for better maintainability.');
}

console.log('Starting CSS reference update process...\n');
updateReferences().catch(error => {
    console.error('Error during update:', error);
    process.exit(1);
});

