const fs = require('fs').promises;

async function calculateSavings() {
    const cssFiles = {
        'aboutUs': { original: 16699 },      // From previous logs
        'auth': { original: 14077 },
        'checkOut': { original: 35403 },
        'confirm': { original: 538 },
        'homePage': { original: 45258 },
        'loginModal': { original: 18788 },
        'viewCart': { original: 13427 },
        'Login': { original: 1592 },
        'AdminSetup': { original: 2509 }
    };

    let totalOriginal = 0;
    let totalMinified = 0;

    console.log('Calculating size reduction...\n');
    console.log('File Size Comparison:');
    console.log('------------------------------------------');
    console.log('File Name        Original    Minified   Reduction');
    console.log('------------------------------------------');

    for (const [name, data] of Object.entries(cssFiles)) {
        try {
            let minPath = `public/css/${name}.min.css`;
            if (name === 'Login') {
                minPath = 'public/css/components/Login.min.css';
            } else if (name === 'AdminSetup') {
                minPath = 'src/components/AdminSetup.min.css';
            }

            const stats = await fs.stat(minPath);
            const minSize = stats.size;
            
            const reduction = ((data.original - minSize) / data.original * 100).toFixed(2);
            
            console.log(
                `${name.padEnd(15)} ${
                    data.original.toString().padStart(8)} B  ${
                    minSize.toString().padStart(8)} B   ${
                    reduction.toString().padStart(6)}%`
            );

            totalOriginal += data.original;
            totalMinified += minSize;
        } catch (error) {
            console.log(`× Error processing ${name}: ${error.message}`);
        }
    }

    const totalReduction = ((totalOriginal - totalMinified) / totalOriginal * 100).toFixed(2);
    
    console.log('------------------------------------------');
    console.log(
        `TOTAL          ${
            totalOriginal.toString().padStart(8)} B  ${
            totalMinified.toString().padStart(8)} B   ${
            totalReduction.toString().padStart(6)}%`
    );
    console.log('------------------------------------------');

    // Calculate human-readable sizes
    const originalKB = (totalOriginal / 1024).toFixed(2);
    const minifiedKB = (totalMinified / 1024).toFixed(2);
    const savedKB = ((totalOriginal - totalMinified) / 1024).toFixed(2);

    console.log('\nSummary:');
    console.log(`Original size: ${originalKB} KB`);
    console.log(`Minified size: ${minifiedKB} KB`);
    console.log(`Space saved: ${savedKB} KB (${totalReduction}%)`);
    
    // Calculate download time improvement
    const slowConnection = 2000; // 2 Mbps (typical 3G)
    const fastConnection = 8000; // 8 Mbps (typical 4G)
    
    const originalSlowTime = (totalOriginal * 8 / slowConnection).toFixed(2);
    const minifiedSlowTime = (totalMinified * 8 / slowConnection).toFixed(2);
    const originalFastTime = (totalOriginal * 8 / fastConnection).toFixed(2);
    const minifiedFastTime = (totalMinified * 8 / fastConnection).toFixed(2);

    console.log('\nDownload Time Improvements:');
    console.log('On 3G (2 Mbps):');
    console.log(`- Original: ${originalSlowTime} seconds`);
    console.log(`- Minified: ${minifiedSlowTime} seconds`);
    console.log('\nOn 4G (8 Mbps):');
    console.log(`- Original: ${originalFastTime} seconds`);
    console.log(`- Minified: ${minifiedFastTime} seconds`);
}

console.log('Analyzing CSS size reduction...\n');
calculateSavings().catch(error => {
    console.error('Error during analysis:', error);
    process.exit(1);
});

