// src/services/auth.service.js
const useragent = require("useragent");
const userModel = require("../modells/user/userModells");
const config = require("../Config/authConfig");

const {
  signAccessToken,
  signRefreshToken,
  generateTokenId,
} = require("../utils/authTokens");

const createTokensAndCookie = async (
  user,
  req,
  res,
  oldRefreshToken = null
) => {
  if (!req || !res) {
    throw new Error("req or res not passed to createTokensAndCookie");
  }

  const accessToken = signAccessToken({ sub: user._id.toString() });

  const refreshToken = signRefreshToken({
    sub: user._id.toString(),
    jti: generateTokenId(),
  });

  const agent = useragent.parse(req?.headers?.["user-agent"] || "unknown");

  const tokenRecord = {
    token: refreshToken,
    ip: req.ip,
    userAgent: agent.toString(),
    revoked: false,
    createdAt: new Date(),
  };

  if (oldRefreshToken) {
    await userModel.updateOne(
      { _id: user._id, "refreshTokens.token": oldRefreshToken },
      {
        $set: {
          "refreshTokens.$.revoked": true,
          "refreshTokens.$.replacedByToken": refreshToken,
        },
      }
    );
  }

  await userModel.updateOne(
    { _id: user._id },
    { $push: { refreshTokens: tokenRecord } }
  );

  res.cookie("refreshToken", refreshToken, {
    ...config.cookieOptions,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 30,
  });

  return { accessToken };
};

module.exports= createTokensAndCookie ;
