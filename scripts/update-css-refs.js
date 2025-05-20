const fs = require('fs').promises;
const path = require('path');

async function updateHTMLFiles() {
    const htmlFiles = [
        'unauthorized.html',
        'browseProduct/browseProduct.html',
        'public/404.html',
        'public/forgot-password.html',
        'public/index.html',
        'public/reset-password.html',
        'public/aboutUs/aboutUs.html',
        'public/checkOut/checkOut.html',
        'public/confirmation/confirm.html',
        'public/viewCart/viewCart.html'
    ];

    const cssReplacements = {
        'aboutUs.css': 'aboutUs.min.css',
        'auth.css': 'auth.min.css',
        'checkOut.css': 'checkOut.min.css',
        'confirm.css': 'confirm.min.css',
        'homePage.css': 'homePage.min.css',
        'loginModal.css': 'loginModal.min.css',
        'viewCart.css': 'viewCart.min.css',
        'Login.css': 'Login.min.css',
        'AdminSetup.css': 'AdminSetup.min.css',
        'browseProduct.css': 'browseProduct.min.css'
    };

    console.log('Updating HTML files to use minified CSS...\n');

    for (const file of htmlFiles) {
        try {
            console.log(`Processing ${file}...`);
            let content = await fs.readFile(file, 'utf8');
            let originalContent = content;
            let changes = 0;

            // Create backup of original file
            await fs.writeFile(`${file}.backup`, content);

            // Replace CSS references
            for (const [original, minified] of Object.entries(cssReplacements)) {
                const regex = new RegExp(`(href=["'].*?)${original}(["'])`, 'g');
                const newContent = content.replace(regex, `$1${minified}$2`);
                if (newContent !== content) {
                    changes++;
                    content = newContent;
                }
            }

            // Only write if changes were made
            if (changes > 0) {
                await fs.writeFile(file, content);
                console.log(`✓ Updated ${changes} CSS reference(s) in ${file}`);
                console.log(`  Created backup: ${file}.backup`);
            } else {
                console.log(`- No CSS references to update in ${file}`);
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`⚠ ${file} not found, skipping...`);
            } else {
                console.error(`× Error processing ${file}:`, error.message);
            }
        }
    }
}

console.log('Starting HTML updates...\n');
updateHTMLFiles().then(() => {
    console.log('\nHTML updates complete!');
    console.log('You can now verify the changes and remove the original CSS files if desired.');
}).catch(error => {
    console.error('Error during updates:', error);
    process.exit(1);
});

