const fs = require('fs').promises;
const path = require('path');

/**
 * Validates and fixes common CSS syntax issues
 * @param {string} content CSS content to validate and fix
 * @return {object} Object containing the fixed content and whether it changed
 */
async function validateAndFixCSS(content) {
    // Store original content for comparison
    const originalContent = content;
    
    // Create a temporary version without comments for brace counting
    // This avoids confusion with braces in comments
    let tempContent = content.replace(/\/\*[\s\S]*?\*\//g, '');
    
    // Fix any incomplete media queries
    tempContent = tempContent.replace(/@media[^{]*\{([^}]*$)/g, (match, p1) => {
        return match + '\n}';
    });
    
    // Fix any incomplete keyframes
    tempContent = tempContent.replace(/@keyframes[^{]*\{([^}]*$)/g, (match, p1) => {
        return match + '\n}';
    });

    // Count braces in a more thorough way
    let stack = [];
    let lines = tempContent.split('\n');
    let fixes = [];
    
    // Track open braces positions
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i];
        for (let j = 0; j < line.length; j++) {
            if (line[j] === '{') {
                stack.push({ line: i, char: j });
            } else if (line[j] === '}') {
                if (stack.length > 0) {
                    stack.pop();
                } else {
                    // Extra closing brace found
                    fixes.push({ line: i, type: 'remove' });
                }
            }
        }
    }

    // Add missing closing braces
    while (stack.length > 0) {
        const lastOpen = stack.pop();
        fixes.push({ line: lastOpen.line + 1, type: 'add' });
    }

    // Switch to working with the original content including comments
    lines = content.split('\n');
    
    // Apply fixes from bottom to top to avoid index shifting
    fixes.sort((a, b) => b.line - a.line);
    for (const fix of fixes) {
        if (fix.type === 'add') {
            lines.splice(fix.line, 0, '}');
        } else if (fix.type === 'remove' && lines[fix.line]) {
            lines[fix.line] = lines[fix.line].replace(/}/g, '');
        }
    }

    // Fix specific pattern in aboutUs.css - extra closing brace after header1
    let contentStr = lines.join('\n');
    contentStr = contentStr.replace(/\.header1\s*{[^}]*}\s*}/, match => {
        return match.slice(0, -1); // Remove the extra closing brace
    });
    
    // Basic cleanup of whitespace and formatting
    contentStr = contentStr
        .replace(/\s+}/g, ' }')
        .replace(/{\s+/g, ' { ')
        .replace(/\n\s*\n\s*\n/g, '\n\n')
        .replace(/;\s*}/g, ';}')
        .trim();

    // Return whether content changed and the fixed content
    return {
        changed: contentStr !== originalContent,
        content: contentStr
    };
}

async function fixCSSFiles() {
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

    let fixedCount = 0;
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
            
            // Create backup of original file
            try {
                await fs.writeFile(`${file}.backup`, content);
            } catch (backupError) {
                console.log(`⚠ Could not create backup of ${file}: ${backupError.message}`);
            }
            
            // Fix and validate CSS
            const { changed, content: fixedContent } = await validateAndFixCSS(content);
            
            // Always write the content to ensure all files are processed consistently
            await fs.writeFile(file, fixedContent);
            
            if (changed) {
                console.log(`✓ Fixed ${file}`);
                console.log(`  Created backup: ${file}.backup`);
                fixedCount++;
            } else {
                console.log(`✓ ${file} is already valid`);
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`⚠ ${file} not found, skipping...`);
                skippedCount++;
            } else {
                console.error(`× Error processing ${file}:`, error.message);
                errorCount++;
            }
        }
    }

    return { fixedCount, errorCount, skippedCount };
}

console.log('Starting CSS fixes...\n');
fixCSSFiles().then(({ fixedCount, errorCount, skippedCount }) => {
    console.log('\nCSS fixes summary:');
    console.log(`- Fixed: ${fixedCount} files`);
    console.log(`- Errors: ${errorCount} files`);
    console.log(`- Skipped: ${skippedCount} files`);
    console.log('\nCSS fixes complete! You can now run the minification script.');
}).catch(error => {
    console.error('Error during CSS fixes:', error);
    process.exit(1);
});

