const jwt = require("jsonwebtoken");
const crypto = require("crypto"); // <-- added
const config = require("./../Config/authConfig"); // <-- import your config
const dotenv = require("dotenv");
dotenv.config({ path: "./.env" });




function signAccessToken(payload) {
  return jwt.sign(payload, config.jwtAccessSecret, {
    expiresIn: config.accessTokenExpiry
  });
}

function signRefreshToken(payload) {
  // we sign a refresh token too, but create a random token id to store server-side
  return jwt.sign(payload, config.jwtRefreshSecret, {
    expiresIn: config.refreshTokenExpiry
  });
}

// helper to generate opaque token id (if you prefer not to keep JWT refresh)
function generateTokenId() {
  return crypto.randomBytes(32).toString("hex");
}


  
module.exports={
    signRefreshToken,
    signAccessToken,
    generateTokenId
}