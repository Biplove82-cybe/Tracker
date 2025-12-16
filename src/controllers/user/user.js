 const userModel =require("../../modells/user/user");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const useragent = require("useragent");
// const useragent = require("useragent");
const geoip = require("geoip-lite");
const crypto = require("crypto");
const createTokensAndSetCookie = require("../../utils/authService");
const config = require("../../Config/authConfig"); 




// Register user
const userRegister = async (req, res) => {
  try {
    const { name, emp_id, email, phone, department, gender, role, password, description } = req.body;

    if (!name || !emp_id || !email || !password) {
      return res.status(400).json({ msg: "All required fields must be provided" });
    }

    // Check for existing user
    const existingUser = await userModel.findOne({ $or: [{ emp_id }, { email }] });
    if (existingUser) {
      return res.status(409).json({ msg: "Employee ID or Email already exists" });
    }

    // const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new userModel({
      name,
      emp_id,
      email,
      phone,
      department,
      gender,
      role,
      description,
      password,
    });

    await newUser.save();

    res.status(200).json({ msg: "User registered successfully", userID: newUser._id });
  } catch (error) {
    res.status(500).json({ msg: "Server error: " + error.message });
  }
};

// Delete user
const deleteUser = async (req, res) => {
  const userId = req.params._id;

  try {
    const deletedUser = await userModel.findByIdAndDelete(userId);

    if (!deletedUser) return res.status(404).json({ message: "User not found" });

    res.status(200).json({ message: "User deleted successfully", user: deletedUser });
  } catch (error) {
    res.status(500).json({ message: "Error deleting user", error: error.message });
  }
};

// Login user
const login = async (req, res) => {
 try {
    const { name, emp_id, email, password } = req.body;

    // 🔹 Basic validation
    if (!password) {
      return res.status(400).json({ msg: "Password is required" });
    }

    const identity = (name || emp_id || email)?.trim();
    if (!identity) {
      return res
        .status(400)
        .json({ msg: "Enter username, emp_id, or email" });
    }

    // 🔹 Find user (case-insensitive for name/email)
    const user = await userModel
      .findOne({
        $or: [
          { email: new RegExp(`^${identity}$`, "i") },
          { name: new RegExp(`^${identity}$`, "i") },
          { emp_id: identity },
        ],
      })
      .select("+password");

    if (!user) {
      return res.status(401).json({ msg: "Invalid credentials" });
    }

    // 🔒 Account lock check
    if (user.isLocked()) {
      return res.status(423).json({
        msg: "Account temporarily locked. Try again later.",
      });
    }

    // 🔑 Password check
    const isValid = await user.comparePassword(password);
    if (!isValid) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = Date.now() + 10 * 60 * 1000; // 10 min
      }

      await user.save();
      return res.status(401).json({ msg: "Invalid credentials" });
    }

    // ✅ Successful login → reset attempts
    user.failedLoginAttempts = 0;
    user.lockUntil = undefined;

    const agent = useragent.parse(req.headers["user-agent"] || "");
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0] ||
      req.socket.remoteAddress ||
      req.ip;

    const geo = geoip.lookup(ip);

    const fingerprint = crypto
      .createHash("sha256")
      .update(agent.toString() + ip)
      .digest("hex");

    const deviceData = {
      ip,
      userAgent: agent.toString(),
      browser: agent.family,
      os: agent.os.toString(),
      device: agent.device.toString(),
      fingerprint,
      location: geo
        ? {
            country: geo.country,
            region: geo.region,
            city: geo.city,
            timezone: geo.timezone,
            latitude: geo.ll[0],
            longitude: geo.ll[1]
          }
        : null,
      lastSeen: new Date()
    };

    /* Devices */
    user.devices = user.devices.filter(
      d => d.fingerprint !== fingerprint
    );
    user.devices.push(deviceData);

    /* Login history (latest 5) */
    user.loginHistory.unshift({
      ...deviceData,
      loggedInAt: new Date()
    });
    user.loginHistory = user.loginHistory.slice(0, 5);

    await user.save();

const { accessToken } = await createTokensAndSetCookie(
  user,
  req,
  res
);

return res.status(200).json({
  accessToken,
  expiresIn: config.accessTokenExpiry,
  msg: "Login successful",
});

  
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({
      message: "Login failed",
      error: err.message,
    });
}};

// Get all user
const getUser = async (req, res) => {
  try {
    const data = await userModel.find();
    res.status(200).json(data);
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};

// Refresh token
const refreshToken = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    if (!token) return res.status(401).json({ message: "Missing refresh token" });

    let payload;
    try {
      payload = jwt.verify(token, config.jwtRefreshSecret);
    } catch (e) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const user = await userModel.findById(payload.sub);
    if (!user) return res.status(401).json({ message: "User not found" });

    const tokenRecord = user.refreshTokens.find(t => t.token === token);
    if (!tokenRecord || tokenRecord.revoked) {
      user.refreshTokens = [];
      await user.save();
      return res.status(401).json({ message: "Refresh token revoked. Please login again." });
    }

    const { accessToken } = await createTokensAndSetCookie(user, res, req, token);
    res.json({ accessToken, expiresIn: config.accessTokenExpiry });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Refresh failed" });
  }
};
//logout 

const logout = async (req, res) => {
   try {
    const userId = req.user._id;

    if (!userId) {
      return res.status(401).json({ msg: "Unauthorized" });
    }
    await userModel.updateOne(
      { _id: userId },
      { $set: { devices: [] } }
    );
    res.clearCookie("refreshToken");

    res.status(200).json({ msg: "Logged out from all devices successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Logout failed" });
  }
};


module.exports = {
  userRegister,
  deleteUser,
  login,
  getUser,
  refreshToken,
  logout,
};
