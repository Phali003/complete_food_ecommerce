const fs = require('fs').promises;
const path = require('path');

async function cleanupProject() {
    // Original CSS files to remove
    const cssFiles = [
        'public/css/aboutUs.css',
        'public/css/auth.css',
        'public/css/checkOut.css',
        'public/css/confirm.css',
        'public/css/homePage.css',
        'public/css/loginModal.css',
        'public/css/viewCart.css',
        'public/css/components/Login.css',
        'src/components/AdminSetup.css',
        'browseProduct/browseProduct.css'
    ];

    // Backup CSS files to remove
    const backupFiles = cssFiles.map(file => `${file}.backup`);

    // HTML backup files to remove
    const htmlBackupFiles = [
        'public/index.html.backup',
        'public/reset-password.html.backup',
        'public/aboutUs/aboutUs.html.backup',
        'public/checkOut/checkOut.html.backup',
        'public/confirmation/confirm.html.backup',
        'public/viewCart/viewCart.html.backup'
    ];

    // All files to remove
    const allFilesToRemove = [...cssFiles, ...backupFiles, ...htmlBackupFiles];

    console.log('Starting project cleanup...\n');
    
    let removedCount = 0;
    let skippedCount = 0;

    for (const file of allFilesToRemove) {
        try {
            // If it's a CSS file (not a backup), verify minified version exists
            if (file.endsWith('.css') && !file.endsWith('.backup')) {
                const minFile = file.replace('.css', '.min.css');
                try {
                    await fs.access(minFile);
                } catch (error) {
                    console.log(`⚠ Minified version of ${file} not found, skipping removal`);
                    skippedCount++;
                    continue;
                }
            }

            // Delete the file
            await fs.unlink(file);
            console.log(`✓ Removed ${file}`);
            removedCount++;
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`- ${file} already removed or doesn't exist`);
                skippedCount++;
            } else {
                console.error(`× Error removing ${file}:`, error.message);
                skippedCount++;
            }
        }
    }

    console.log('\nCleanup Summary:');
    console.log(`- Removed: ${removedCount} files`);
    console.log(`- Skipped: ${skippedCount} files`);
    console.log('\nProject cleanup complete.');
    console.log('The project now contains only the essential files with minified CSS.');
}

cleanupProject().catch(error => {
    console.error('Error during project cleanup:', error);
    process.exit(1);
});

