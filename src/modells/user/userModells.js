const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const config = require("../../Config/authConfig");

const RefreshTokenSchema = new mongoose.Schema(
  {
    token: String,
    createdAt: { type: Date, default: Date.now },
    revoked: { type: Boolean, default: false },
    replacedByToken: { type: String },
    ip: String,
    userAgent: String,
  },
  { _id: false }
);

const DeviceSchema = new mongoose.Schema(
  {
    ip: String,
    userAgent: String,
    browser: String,
    os: String,
    device: String,
    location: {
      country: String,
      region: String,
      city: String,
      timezone: String,
      ll: [Number],
    },
    lastSeen: Date,
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const LoginHistorySchema = new mongoose.Schema(
  {
    ip: String,
    userAgent: String,
    browser: String,
    os: String,
    device: String,
    location: {
      country: String,
      region: String,
      city: String,
      timezone: String,
      ll: [Number],
    },
    loggedInAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

// ----------------- Main User Schema -----------------
const userSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true, required: true },
    gender: { type: String, trim: true, required: true },
    emp_id: { type: String, trim: true, required: true, unique: true },
    email: { type: String, trim: true, required: true, unique: true, lowercase: true },
    password: { type: String, required: true, select: false },
    phone: { type: String },
    department: { type: String },
    role: { type: String, default: "user", index: true },
    otp: { type: Number, default: null },
    description: { type: String, default: "registered" },
    isEmailVerified: { type: Boolean, default: false },
    twoFA: {
      enabled: { type: Boolean, default: false },
      secret: { type: String },
    },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    refreshTokens: [RefreshTokenSchema],
    devices: [DeviceSchema],
    loginHistory: [LoginHistorySchema],
  },
  { timestamps: true }
);

// ----------------- Indexes for Performance -----------------
userSchema.index({ email: 1 });
userSchema.index({ emp_id: 1 });
userSchema.index({ role: 1 });

// ----------------- Pre-save hooks -----------------
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = config.bcryptSaltRounds || 10;
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// ----------------- Methods -----------------
userSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.isLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Optional: increment failed login attempts & lock account
userSchema.methods.incLoginAttempts = async function () {
  const maxAttempts = config.maxLoginAttempts || 5;
  const lockTime = config.lockTime || 2 * 60 * 60 * 1000; // 2 hours
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.failedLoginAttempts = 1;
    this.lockUntil = undefined;
  } else {
    this.failedLoginAttempts += 1;
    if (this.failedLoginAttempts >= maxAttempts && !this.isLocked()) {
      this.lockUntil = Date.now() + lockTime;
    }
  }
  await this.save();
};
module.exports = mongoose.models.User || mongoose.model("User", userSchema);