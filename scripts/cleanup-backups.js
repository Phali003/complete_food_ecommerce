const fs = require('fs').promises;
const path = require('path');

async function cleanupBackups() {
    // Directories to check for backup files
    const directories = [
        'public',
        'public/aboutUs',
        'public/checkOut',
        'public/confirmation',
        'public/viewCart'
    ];

    console.log('Cleaning up HTML backup files...\n');
    let removedCount = 0;

    for (const dir of directories) {
        try {
            // Get all files in directory
            const files = await fs.readdir(dir);
            
            // Filter for .backup files
            const backupFiles = files.filter(file => file.endsWith('.backup'));
            
            // Remove each backup file
            for (const file of backupFiles) {
                const filePath = path.join(dir, file);
                await fs.unlink(filePath);
                console.log(`✓ Removed: ${filePath}`);
                removedCount++;
            }
        } catch (error) {
            console.error(`× Error processing ${dir}:`, error.message);
        }
    }

    console.log('\nCleanup Summary:');
    console.log(`Total backup files removed: ${removedCount}`);
}

console.log('Starting backup cleanup...\n');
cleanupBackups().catch(error => {
    console.error('Error during cleanup:', error);
    process.exit(1);
});

