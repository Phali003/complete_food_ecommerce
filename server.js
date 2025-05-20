const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const fs = require("fs");
require("dotenv").config();
const jwt = require("jsonwebtoken");

// Check for email domain configuration
if (!process.env.EMAIL_DOMAIN && process.env.NODE_ENV === 'production') {
  console.warn('EMAIL_DOMAIN environment variable is not set. This may cause CORS issues with email links.');
}

// Import routes and database connection after setting DEBUG_URL
const { testConnection } = require("./config/database.js");
const authRoutes = require("./routes/auth");
const productRoutes = require("./api/products/products");
const cartRoutes = require("./api/cart/cart");
const adminRoutes = require("./api/admin/admin");
const { protect } = require("./middleware/auth");
const ejs = require("ejs");
const app = express();
const PORT = process.env.PORT || 3000;

// Configure EJS as view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'", 
          "'unsafe-inline'", 
          "https://code.jquery.com",
          "https://cdn.jsdelivr.net",
          "https://cdnjs.cloudflare.com",
          "https://ka-f.fontawesome.com"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
          "https://cdn.jsdelivr.net"
        ],
        imgSrc: ["'self'", "data:", "https:", "*"],
        fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "data:", "*"],
        connectSrc: ["'self'", "https://ka-f.fontawesome.com", "ws:", "wss:", "*"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
      },
    },
  })
);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === "production" ? 100 : 1000, // Increase limit for development
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again later",
});

// Only apply rate limiting in production
if (process.env.NODE_ENV === "production") {
  app.use(limiter);
}

// Define CORS options - consolidated configuration
// Define CORS options - consolidated for all CORS handling
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl requests)
    if (!origin) return callback(null, true);
    
    // In development, allow all origins
    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    // In production, allow Render domains and explicitly defined origins
    if (origin.endsWith('.onrender.com')) {
      return callback(null, true);
    }
    
    // Check against specific allowed origins
    const allowedOrigins = [
      'https://fresh-eats-market.onrender.com',
      process.env.FRONTEND_URL,
      process.env.EMAIL_DOMAIN
    ].filter(Boolean);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked request from origin: ${origin}`);
      callback(new Error('CORS: Origin not allowed'));
    }
  },
  credentials: true, // Critical for authentication cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With',
    'Accept',
    'Origin',
    'Access-Control-Allow-Headers',
    'Access-Control-Request-Method',
    'Access-Control-Request-Headers'
  ],
  exposedHeaders: ['Set-Cookie'],
  maxAge: 86400, // 24 hours
  preflightContinue: false, // Do not pass preflight requests to handlers
  optionsSuccessStatus: 204 // Return 204 for OPTIONS requests
};

// Apply CORS middleware - must come before any route handlers
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure secure cookie settings
const cookieConfig = {
  httpOnly: true, // Always enable httpOnly for security
  secure: process.env.NODE_ENV === "production", // Secure in production
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // None for cross-origin in production, lax for development
  maxAge: parseInt(process.env.COOKIE_MAX_AGE) || 86400000, // 24 hours in milliseconds
  signed: true,
  path: "/",
  // Only set domain in production and handle it correctly for Render
  ...(process.env.NODE_ENV === "production" && {
    domain: process.env.COOKIE_DOMAIN || ".onrender.com" // Explicitly set for all Render subdomains
  })
};

// Log cookie configuration for debugging
console.log('Cookie Configuration:', {
  httpOnly: cookieConfig.httpOnly,
  secure: cookieConfig.secure,
  sameSite: cookieConfig.sameSite,
  domain: cookieConfig.domain || 'not set',
  environment: process.env.NODE_ENV
});

// JWT Configuration
const jwtConfig = {
  secret: process.env.JWT_SECRET,
  options: {
    expiresIn: process.env.JWT_EXPIRES_IN || "24h",
    algorithm: "HS256",
  },
};

// Initialize cookie-parser with the secure cookie secret
app.use(cookieParser(process.env.COOKIE_SECRET));

// Note: JWT verification is now handled by middleware/auth.js with the protect middleware

// Helper function to set secure cookies
app.use((req, res, next) => {
  res.setSecureCookie = (name, value) => {
    res.cookie(name, value, cookieConfig);
  };
  next();
});

// Static files with enhanced configuration
const staticOptions = {
  setHeaders: (res, filePath, stat) => {
    // Don't set CORS headers here since they're handled by the cors middleware
    // This avoids conflicts with the global CORS settings
    
    // Add Vary header to help with caching
    res.set('Vary', 'Origin, Accept-Encoding');

    // Different cache settings based on file type
    if (filePath.endsWith('.html')) {
      // Don't cache HTML files
      res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'Expires': '0'
      });
    } else if (filePath.includes('/css/') || filePath.includes('/js/')) {
      // Allow CSS and JS files to be cached but must revalidate
      res.set('Cache-Control', 'public, max-age=0, must-revalidate');
    } else if (filePath.includes('/assets/')) {
      // Long cache for assets
      res.set('Cache-Control', 'public, max-age=2592000'); // 30 days
    } else {
      // Default caching policy
      res.set('Cache-Control', 'public, max-age=86400'); // 1 day
    }

    // Set security headers for all static files
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block'
    });
  },
  // Ensure proper MIME types
  setMimeTypes: {
    'text/css': ['css'],
    'text/javascript': ['js'],
    'text/html': ['html']
  },
  // Don't serve hidden files
  dotfiles: 'ignore'
};

// Main static file middleware
app.use(express.static(path.join(__dirname, "public"), staticOptions));

// Specific routes with the same options
app.use("/js", express.static(path.join(__dirname, "public/js"), staticOptions));
app.use("/css", express.static(path.join(__dirname, "public/css"), staticOptions));
app.use("/assets", express.static(path.join(__dirname, "public/assets"), staticOptions));
app.use(
  "/assets/myImages",
  express.static(path.join(__dirname, "public/assets/myImages"), staticOptions)
);
app.use(
  "/components",
  express.static(path.join(__dirname, "public/components"))
);
app.use("/pages", express.static(path.join(__dirname, "public/pages")));

// API route logging middleware (removed OPTIONS handling as it's now at the top level)
app.use("/api", (req, res, next) => {
  if (req.method !== 'OPTIONS') {
    console.log(`API Request: ${req.method} ${req.path}`);
  }
  next();
});

app.use((req, res, next) => {
  if (req.url.startsWith("/api")) return next();

  try {
    const url = req.url;

    // Basic validation to catch common problematic URL patterns
    const invalidPatterns = [
      "://", // protocol
      "//", // double slash
      "*", // wildcards
      "+", // regex quantifiers
      "(",
      ")", // regex groups
      "?", // query parameter start without preceding slash or regex quantifier
      ";", // parameter delimiter
    ];

    // Check for invalid patterns
    for (const pattern of invalidPatterns) {
      if (url.includes(pattern)) {
        console.warn(
          `Invalid URL pattern detected: ${url} (contains ${pattern})`
        );
        return res.status(404).send("Not found");
      }
    }

    // Check for malformed route parameters (e.g., ":/" or ":123")
    if (url.includes(":")) {
      if (url.includes(":/") || /:[^a-zA-Z]/.test(url)) {
        console.warn(`Malformed route parameter in URL: ${url}`);
        return res.status(404).send("Not found");
      }
    }

    next();
  } catch (err) {
    console.error(`Error processing URL ${req.url}:`, err);
    return res.status(404).send("Not found");
  }
});

// Keep the existing routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// API routes
// Authentication error handler for auth routes
app.use("/api/auth", (req, res, next) => {
  // Handle authentication specific errors
  try {
    next();
  } catch (error) {
    console.error("Auth route error:", error);
    return res.status(500).json({
      success: false,
      message: "Authentication error",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.use("/api/auth", authRoutes);
app.use("/api/products", protect, productRoutes);
app.use("/api/cart", protect, cartRoutes);

// Page routes
app.get("/view-cart", (req, res) => {
  res.sendFile(path.join(__dirname, "public/viewCart/viewCart.html"));
});

app.get("/checkout", (req, res) => {
  res.sendFile(path.join(__dirname, "public/checkOut/checkOut.html"));
});

app.get("/about-us", (req, res) => {
  res.sendFile(path.join(__dirname, "public/aboutUs/aboutUs.html"));
});

app.get("/confirm", (req, res) => {
  res.sendFile(path.join(__dirname, "public/confirmation/confirm.html"));
});

// Additional route for browsing products can redirect to home
app.get("/browse-products", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// Authentication page routes
app.get("/forgot-password", (req, res) => {
  res.sendFile(path.join(__dirname, "public/forgot-password.html"));
});

// Update the reset-password.html route handler
app.get("/reset-password.html", (req, res) => {
  const token = req.query.token;
  
  // Validate token presence and basic format
  if (!token || token.length < 20) {  // Changed from strict hex validation
    console.warn('Invalid token detected:', token ? 'Invalid length' : 'Missing token');
    return res.redirect('/forgot-password.html');
  }
  
  // Just serve the HTML file with the base URL and token
  fs.readFile(path.join(__dirname, "public/reset-password.html"), 'utf8', (err, html) => {
    if (err) {
      console.error('Error reading reset-password.html:', err);
      return res.status(500).send('Internal Server Error');
    }

    // Construct the base URL
    const protocol = req.protocol;
    const host = req.get('host');
    const baseUrl = `${protocol}://${host}`;

    // Extra token sanitization
    const sanitizedToken = token
      .replace(/[<>'"]/g, '') // Remove potentially dangerous characters
      .trim();

    // Debug the token before injection
    console.log('Token debug:', {
      originalLength: token.length,
      sanitizedLength: sanitizedToken.length,
      baseUrl: baseUrl
    });

    // Update the token injection with modified script
    const modifiedHtml = html.replace(
      '</head>',
      `<script>
        // Immediately set the token and base URL
        (function() {
            window.BASE_URL = "${baseUrl}";
            window.RESET_TOKEN = "${sanitizedToken}";
            
            // Debug token set
            console.log('Token set debug:', {
                exists: typeof window.RESET_TOKEN === 'string',
                length: window.RESET_TOKEN ? window.RESET_TOKEN.length : 0,
                baseUrl: window.BASE_URL
            });
        })();
      </script></head>`
    );

    // Set security headers
    res.set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Content-Type': 'text/html',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block'
    });

    res.send(modifiedHtml);
  });
});

// Note: The actual password reset should only happen when the form is submitted via the API


// Admin routes for pages and other admin functionalities
app.use("/api/admin", protect, adminRoutes);

// Very simple catch-all that doesn't try to parse URL patterns
app.use((req, res, next) => {
  if (req.method !== "GET" || res.headersSent) {
    return next();
  }

  // Very basic URL validation - reject anything suspicious
  const url = req.url;
  if (
    url.includes(":") ||
    url.includes("*") ||
    url.includes("?") ||
    url.includes("+") ||
    url.includes("(") ||
    url.includes(")")
  ) {
    return res.status(404).send("Not found");
  }

  // Simple static file handling for index.html
  res.sendFile(path.join(__dirname, "public/index.html"), (err) => {
    if (err) {
      return res.status(404).send("Not found");
    }
  });
});

app.use((err, req, res, next) => {
    console.error("Server error:", err.stack);

    // Handle CORS errors first
    if (err.message && err.message.includes('CORS')) {
      console.warn('CORS Error:', {
        origin: req.headers.origin,
        method: req.method,
        path: req.path,
        error: err.message
      });
      
      // For OPTIONS requests, let the CORS middleware handle it
      if (req.method === 'OPTIONS') {
        return res.status(204).end();
      }
      
      // For CORS errors, return 403
      return res.status(403).json({
        success: false,
        error: 'CORS error: Origin not allowed',
        details: process.env.NODE_ENV === 'development' ? err.message : undefined
      });
    }

    const statusCode = err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    const isJsonRequest =
      req.xhr ||
      req.headers.accept?.indexOf("json") !== -1 ||
      req.path.startsWith("/api");

    if (isJsonRequest) {
      res.status(statusCode).json({
        success: false,
        error: message,
        details: process.env.NODE_ENV === "development" ? err.stack : undefined
      });
  } else {
    res.status(statusCode).send(`
      <html>
        <head><title>Error</title></head>
        <body>
          <h1>Error ${statusCode}</h1>
          <p>${message}</p>
          ${
            process.env.NODE_ENV === "development"
              ? `<pre>${err.stack}</pre>`
              : ""
          }
        </body>
      </html>
    `);
  }
});

const startServer = async () => {
  try {
    const connected = await testConnection();
    if (!connected) {
      console.error("Failed to connect to MySQL database");
      process.exit(1);
    }

    app.set("strict routing", true);
    app.set("case sensitive routing", true);

    app.listen(PORT, () => {
      console.log(
        `Server running in ${
          process.env.NODE_ENV || "development"
        } mode on port ${PORT}`
      );
    });
  } catch (error) {
    console.error("Error starting server:", error);
    process.exit(1);
  }
};

process.on("unhandledRejection", (err) => {
  console.error("Unhandled Promise Rejection:", err);
  process.exit(1);
});

process.on("uncaughtException", (err) => {
  // Log all uncaught exceptions and exit
  console.error("Uncaught Exception:", err);
  process.exit(1);
});

startServer();
