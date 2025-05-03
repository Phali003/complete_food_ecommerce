# Admin Creation and Authentication Flow

## Overview

The Food E-commerce platform has a two-tiered admin system:

1. **Super Admin** - The initial administrator with elevated privileges
2. **Regular Admins** - Additional administrators created by the Super Admin

## Admin Creation Process

### Initial Super Admin Setup

The system allows for creating exactly one Super Admin through the `/setup-initial-admin` endpoint. This process:

1. Checks if any admin already exists in the system
2. Requires a special setup code (stored in environment variables)
3. Creates a user with `role = 'admin'` and `is_super_admin = true` flags
4. Can only be performed once - attempts to create another Super Admin will be rejected

```javascript
// Example from auth.js
// Check if any admin already exists
const [admins] = await connection.execute(
    'SELECT COUNT(*) as count FROM users WHERE role = ?',
    ['admin']
);

if (admins[0].count > 0) {
    return res.status(400).json({
        success: false,
        message: "Admin account already exists. This endpoint is only for initial setup."
    });
}
```

### Additional Admin Creation

Once a Super Admin exists, they can create additional admin accounts through the `/create-admin` endpoint:

1. This endpoint requires authentication with a Super Admin account
2. It creates users with `role = 'admin'` but `is_super_admin = false`
3. Only the Super Admin can create new admin accounts
4. There's no limit to how many regular admins can be created

```javascript
// Example from auth.js
// Check if the requesting user is a super admin
if (!req.user.is_super_admin) {
    return res.status(403).json({
        success: false,
        message: "Only super admins can create new administrators"
    });
}
```

## Authentication Flow

1. Both regular users and admins use the same login endpoint
2. The login response includes:
   - `role`: User role ("user" or "admin")
   - `isAdmin`: Boolean flag 
   - `token`: JWT authentication token

3. The frontend checks the role/isAdmin value to redirect to the appropriate dashboard:
   - Admin users go to `/admin/dashboard` 
   - Regular users go to `/user/dashboard`

## Security Considerations

- The initial admin setup requires a secure setup code
- Only authenticated Super Admins can create additional admins
- The Super Admin flag is protected and cannot be self-assigned

