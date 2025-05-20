const bcrypt = require('bcryptjs'); // We'll use bcryptjs since that's what auth.js uses

async function testBcrypt() {
    try {
        console.log('Starting bcrypt test for admin credentials...');
        
        // Admin credentials from init.sql
        const adminPassword = 'admin123';
        const storedHash = '$2b$10$1JG6hVjGvM2OHQqKsVpKZ.PDtZfzzR.JFWn7YjIawxND4FMX/Cv9O';
        
        // Test verification with stored hash
        console.log('Testing admin password verification...');
        const isValid = await bcrypt.compare(adminPassword, storedHash);
        console.log(`Admin password verification result: ${isValid}`);
        
        // Generate a new hash for comparison
        console.log('\nGenerating new hash with same password...');
        const salt = await bcrypt.genSalt(10);
        const newHash = await bcrypt.hash(adminPassword, salt);
        console.log(`New hash generated: ${newHash}`);
        
        // Verify the new hash works
        const newHashValid = await bcrypt.compare(adminPassword, newHash);
        console.log(`New hash verification result: ${newHashValid}`);
        
        return {
            originalHashValid: isValid,
            newHashValid: newHashValid
        };
    } catch (error) {
        console.error('Bcrypt test failed:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Run the test
testBcrypt()
    .then(result => {
        console.log('\nTest results:', result);
    })
    .catch(error => {
        console.error('Test execution error:', error);
    });
