const { testDirectConnection } = require('./config/database');

async function testConnection() {
    try {
        const result = await testDirectConnection();
        console.log('Test result:', result);
    } catch (error) {
        console.error('Test failed:', error);
    }
}

testConnection();
