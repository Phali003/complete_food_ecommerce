// Configure CSRF protection
const csrfProtection = csrf({ 
  cookie: true,
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Middleware to handle CSRF
app.use((req, res, next) => {
  // Skip CSRF for API routes
  if (req.path.startsWith('/api/')) {
    next();
  } else {
    csrfProtection(req, res, next);
  }
});

// Add CSRF token to res.locals and cookies
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) {
    const token = req.csrfToken();
    res.cookie('XSRF-TOKEN', token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax'
    });
  }
  next();
});

// Handle CSRF errors
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      success: false,
      message: 'Invalid form submission. Please try again.'
    });
  }
  next(err);
});
