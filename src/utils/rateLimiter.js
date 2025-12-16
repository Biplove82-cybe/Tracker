const rateLimit = require("express-rate-limit");

const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 250, // allow 250 requests per IP per window
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers

  message: {
    success: false,
    statusCode: 429,
    message: "Too many requests, please try again after some time.",
  },

  handler: (req, res, next, options) => {
    res.status(options.statusCode).json(options.message);
  },
});


const authlimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // allow 250 requests per IP per window
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers

  message: {
    success: false,
    statusCode: 429,
    message: "Too many requests, please try again after some time.",
  },

  handler: (req, res, next, options) => {
    res.status(options.statusCode).json(options.message);
  },
});

module.exports = apiRateLimiter;
