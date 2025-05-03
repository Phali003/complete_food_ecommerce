# Initial Admin Setup Guide for Deployed Environment

This guide explains how to set up the first administrator account (Super Admin) for your Food E-commerce platform after deployment.

## 1. Pre-Deployment Preparation

Before deploying your application, complete these preparation steps:

### 1.1. Generate a Strong Setup Code

Create a strong, random setup code that will be used for the initial admin configuration.

**Option 1: Using the included utility script:**

```bash
# Run the setup code generator script
node scripts/generate-setup-code.js

# Output example:
# ===== READABLE ADMIN SETUP CODE =====
# zJN6-yHmp-2GTb-X8f7-dP4K-3aLc
# =================================
```

You can customize the generated code:
```bash
# Generate a secure code in base64 format
node scripts/generate-setup-code.js --type=secure

# Generate a longer readable code
node scripts/generate-setup-code.js --length=32

# Generate a readable code without separators
node scripts/generate-setup-code.js --no-separators
```

**Option 2: Directly in Node.js code:**

```javascript
// Import the utility
const { generateReadableSetupCode } = require('./utils/securityUtils');

// Generate a readable setup code
const setupCode = generateReadableSetupCode();
console.log('Use this setup code:', setupCode);
```

**Option 3: Using other methods:**

```bash
# Using OpenSSL (if available)
openssl rand -base64 24

# Using Node.js in command line
node -e "console.log(require('crypto').randomBytes(24).toString('base64'))"
```

### 1.2. Configure Environment Variables

Add the setup code to your environment variables during deployment:

```bash
# For production environment
INITIAL_ADMIN_SETUP_CODE=your_secure_random_code_here
JWT_SECRET=your_jwt_secret_here
# Other environment variables...
```

Configuration methods vary depending on your hosting provider:

- **Heroku**: Set in the Dashboard or using the CLI:
  ```bash
  heroku config:set INITIAL_ADMIN_SETUP_CODE=your_secure_random_code_here
  ```

- **Vercel/Netlify**: Configure through the web dashboard in the Environment Variables section

- **AWS/Google Cloud**: Use their secrets management systems

- **Docker**: Add to your docker-compose.yml or pass as arguments

### 1.3. Ensure the Admin Setup Route is Available

Verify the `/setup-initial-admin` endpoint is properly implemented and the AdminSetup component is included in your routes.

## 2. Securely Sharing the Setup Code

The setup code must be securely shared with the person who will create the initial admin account:

### 2.1. Choose a Secure Sharing Method

- **Password Manager**: Share through a secure password manager (1Password, LastPass, Bitwarden)
- **Encrypted Message**: Use encrypted messaging apps like Signal or encrypted email
- **Temporary Secret Sharing Service**: Use a service that allows for one-time viewing and automatic deletion:
  - [One Time Secret](https://onetimesecret.com/)
  - [Password Pusher](https://pwpush.com/)

### 2.2. Avoid Unsecure Methods

DO NOT share the setup code via:
- Plain email
- Regular text messages
- Chat applications without encryption
- Public or shared documents
- Version control systems

### 2.3. Planned Deletion

Instruct the recipient to:
1. Delete the setup code after use
2. Confirm when admin setup is complete

## 3. Creating the Initial Admin Account

After deployment, follow these steps to create the first admin account:

### 3.1. Access the Admin Setup Page

1. Navigate to your deployed application: `https://your-app-domain.com`
2. Click the "Setup admin account" link on the login page or
3. Go directly to: `https://your-app-domain.com/admin-setup`

### 3.2. Complete the Admin Setup Form

Fill in the form with the following information:

1. **Username**: Choose a username for the Super Admin account (e.g., "superadmin")
2. **Email**: Enter a valid email address for account recovery
3. **Password**: Create a strong password (min. 8 characters, mix of letters, numbers, symbols)
4. **Confirm Password**: Repeat the same password
5. **Admin Setup Code**: Enter the secure setup code shared with you

### 3.3. Submit the Form

1. Click "Create Admin Account"
2. If successful, you'll see a success message
3. You'll be automatically redirected to the admin dashboard

### 3.4. Verify Admin Privileges

After login, verify that you have full admin access by:
1. Accessing the admin dashboard
2. Creating a test content item
3. Verifying you can create other admin accounts

## 4. After Initial Setup

Once the Super Admin account is created:

### 4.1. Security Recommendations

1. **Change the Setup Code**: Update the `INITIAL_ADMIN_SETUP_CODE` in your environment variables to prevent further use
2. **Consider Disabling the Setup Route**: If possible, disable the admin setup route in production after initial setup

### 4.2. Creating Additional Admin Accounts

As the Super Admin, you can now create additional admin accounts:

1. Log in with your Super Admin credentials
2. Navigate to "User Management" in the admin dashboard
3. Click "Create New Admin"
4. Fill in the details for the new admin
5. Click "Create Admin"

### 4.3. Admin Account Management

Regular admin accounts can manage the application but cannot:
- Create other admin accounts
- Delete the Super Admin
- Access certain restricted system configuration options

## Troubleshooting

If you encounter issues during the admin setup process:

1. **"Admin already exists" error**: 
   - An admin account already exists in the system
   - Contact your development team for access

2. **"Invalid setup code" error**:
   - Double-check the setup code for typos
   - Verify the environment variable is correctly set

3. **Page not found (404) error**:
   - Ensure the route is properly configured
   - Check that the AdminSetup component is included in your deployment

4. **Server errors (500)**:
   - Check server logs for more details
   - Verify database connection and configuration

