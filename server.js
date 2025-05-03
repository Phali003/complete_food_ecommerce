const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
require("dotenv").config();
const jwt = require("jsonwebtoken");

// Import routes and database connection after setting DEBUG_URL
const { testConnection } = require("./config/database");
const authRoutes = require("./routes/auth");
const pagesRoutes = require("./routes/pages");
const productRoutes = require("./routes/products");
const cartRoutes = require("./routes/cart");
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
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/"],
        imgSrc: ["'self'", "data:"],
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

app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? process.env.FRONTEND_URL
        : "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure secure cookie settings
const cookieConfig = {
  httpOnly: process.env.COOKIE_HTTP_ONLY === 'true',
  secure: process.env.COOKIE_SECURE === 'true', 
  sameSite: process.env.COOKIE_SAME_SITE || 'strict',
  maxAge: parseInt(process.env.COOKIE_MAX_AGE) || 86400000, // 24 hours in milliseconds
  signed: true,
  path: '/'
};

// JWT Configuration
const jwtConfig = {
  secret: process.env.JWT_SECRET,
  options: {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    algorithm: 'HS256'
  }
};

// Initialize cookie-parser with the secure cookie secret
app.use(cookieParser(process.env.COOKIE_SECRET));

// JWT verification middleware
const verifyToken = (req, res, next) => {
  try {
    const token = req.cookies.jwt || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    jwt.verify(token, jwtConfig.secret, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
      }
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({ message: 'Authentication failed' });
  }
};

// Helper function to set secure cookies
app.use((req, res, next) => {
  res.setSecureCookie = (name, value) => {
    res.cookie(name, value, cookieConfig);
  };
  next();
});

// Static files
app.use(express.static(path.join(__dirname, "public")));
app.use('/src/components', express.static(path.join(__dirname, 'src/components')));
app.use("/css", express.static(path.join(__dirname, "css")));
app.use("/assets", express.static(path.join(__dirname, "Assets")));
app.use("/viewcart", express.static(path.join(__dirname, "viewCart")));
app.use("/checkout", express.static(path.join(__dirname, "checkOut")));
app.use("/signing", express.static(path.join(__dirname, "Signing")));
app.use("/aboutus", express.static(path.join(__dirname, "aboutUs")));
app.use("/confirmation", express.static(path.join(__dirname, "confirmation")));

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
  res.sendFile(path.join(__dirname, "index.html"));
});

// API routes
app.use("/api/auth", authRoutes);
app.use("/api/products", verifyToken, productRoutes);
app.use("/api/cart", verifyToken, cartRoutes);

// Page routes
app.get("/view-cart", (req, res) => {
  res.sendFile(path.join(__dirname, "viewCart/viewCart.html"));
});

app.get("/checkout", (req, res) => {
  res.sendFile(path.join(__dirname, "checkOut/checkOut.html"));
});

app.get("/about-us", (req, res) => {
  res.sendFile(path.join(__dirname, "aboutUs/aboutUs.html"));
});

app.get("/confirm", (req, res) => {
  res.sendFile(path.join(__dirname, "confirmation/confirm.html"));
});

// Additional route for browsing products can redirect to home
app.get("/browse-products", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Simple pagesRoutes (non-API) at the end
app.use("/", pagesRoutes);

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
  res.sendFile(path.join(__dirname, "index.html"), (err) => {
    if (err) {
      return res.status(404).send("Not found");
    }
  });
});

app.use((err, req, res, next) => {
  console.error("Server error:", err.stack);

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
      stack: process.env.NODE_ENV === "development" ? err.stack : {},
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
