// API Configuration for different environments
const API_CONFIG = {
  // Base URL that automatically detects environment
  BASE_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:3000'
    : 'https://fresh-eats-market.onrender.com',

  // Helper function to create full API URLs
  getApiUrl: function(endpoint) {
    if (!endpoint.startsWith('/')) {
      endpoint = '/' + endpoint;
    }
    return this.BASE_URL + endpoint;
  }
};
