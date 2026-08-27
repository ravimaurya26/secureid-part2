const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || "development-session-secret-change-me";
const JWT_SECRET =
  process.env.JWT_SECRET || "development-jwt-secret-change-me";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "secureid.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 2
    }
  })
);

// Simple demo stores.
// For production, replace these Maps with a persistent database.
const users = new Map();
const challenges = new Map();
const loginFailures = new Map();

const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 3;
const MAX_LOGIN_FAILURES = 5;
const LOCKOUT_MS = 5 * 60 * 1000;

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function createId() {
  return crypto.randomBytes(18).toString("hex");
}

function generateOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function hashOtp(otp) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(String(otp))
    .digest("hex");
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    mfaEnabled: user.mfaEnabled,
    createdAt: user.createdAt
  };
}

function getLockInfo(email) {
  const record = loginFailures.get(email);
  if (!record) return { locked: false, failures: 0 };

  if (record.lockedUntil && Date.now() >= record.lockedUntil) {
    loginFailures.delete(email);
    return { locked: false, failures: 0 };
  }

  return {
    locked: Boolean(record.lockedUntil && Date.now() < record.lockedUntil),
    failures: record.failures || 0,
    lockedUntil: record.lockedUntil || null
  };
}

function recordLoginFailure(email) {
  const current = getLockInfo(email);
  const failures = current.failures + 1;

  if (failures >= MAX_LOGIN_FAILURES) {
    const lockedUntil = Date.now() + LOCKOUT_MS;
    loginFailures.set(email, { failures, lockedUntil });
    return { locked: true, failures, lockedUntil };
  }

  loginFailures.set(email, { failures });
  return { locked: false, failures };
}

function clearLoginFailures(email) {
  loginFailures.delete(email);
}

function createChallenge(userId, channel, purpose) {
  const challengeId = createId();
  const otp = generateOtp();
  const challenge = {
    challengeId,
    userId,
    channel,
    purpose,
    otpHash: hashOtp(otp),
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts: 0,
    used: false
  };

  challenges.set(challengeId, challenge);

  console.log(
    `\n[SIMULATED ${channel.toUpperCase()}]\nUser ID: ${userId}\nOTP: ${otp}\nExpires in: 5 minutes\n`
  );

  return challenge;
}

function validateChallenge(challengeId, userId, purpose) {
  const challenge = challenges.get(challengeId);

  if (!challenge) {
    return { ok: false, status: 404, message: "OTP challenge not found." };
  }

  if (challenge.userId !== userId || challenge.purpose !== purpose) {
    return { ok: false, status: 403, message: "Invalid OTP challenge." };
  }

  if (challenge.used) {
    return { ok: false, status: 400, message: "This OTP has already been used." };
  }

  if (Date.now() > challenge.expiresAt) {
    challenges.delete(challengeId);
    return { ok: false, status: 400, message: "OTP has expired. Request a new OTP." };
  }

  if (challenge.attempts >= MAX_OTP_ATTEMPTS) {
    challenges.delete(challengeId);
    return {
      ok: false,
      status: 429,
      message: "Maximum OTP attempts reached. Request a new OTP."
    };
  }

  return { ok: true, challenge };
}

// ---------- Registration ----------

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!name || !normalizedEmail || !phone || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, phone and password are required."
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters."
      });
    }

    if (users.has(normalizedEmail)) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      id: createId(),
      name: String(name).trim(),
      email: normalizedEmail,
      phone: String(phone).trim(),
      passwordHash,
      mfaEnabled: false,
      emailVerified: false,
      smsVerified: false,
      createdAt: new Date().toISOString()
    };

    users.set(normalizedEmail, user);

    const challenge = createChallenge(user.id, "email", "registration-email");

    res.status(201).json({
      success: true,
      message: "Registration created. Verify the email OTP.",
      challengeId: challenge.challengeId,
      method: "email"
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.post("/api/send-email-otp", (req, res) => {
  const { challengeId } = req.body;
  const oldChallenge = challenges.get(challengeId);

  if (!oldChallenge) {
    return res.status(404).json({
      success: false,
      message: "Registration challenge not found."
    });
  }

  const user = [...users.values()].find((u) => u.id === oldChallenge.userId);

  if (!user) {
    return res.status(404).json({ success: false, message: "User not found." });
  }

  const challenge = createChallenge(user.id, "email", "registration-email");

  res.json({
    success: true,
    message: "A new email OTP was generated.",
    challengeId: challenge.challengeId,
    method: "email"
  });
});

app.post("/api/verify-email-otp", (req, res) => {
  const { challengeId, otp } = req.body;
  const oldChallenge = challenges.get(challengeId);

  if (!oldChallenge) {
    return res.status(404).json({
      success: false,
      message: "OTP challenge not found."
    });
  }

  const result = validateChallenge(
    challengeId,
    oldChallenge.userId,
    "registration-email"
  );

  if (!result.ok) {
    return res.status(result.status).json({
      success: false,
      message: result.message
    });
  }

  result.challenge.attempts += 1;

  if (hashOtp(otp) !== result.challenge.otpHash) {
    if (result.challenge.attempts >= MAX_OTP_ATTEMPTS) {
      challenges.delete(challengeId);
      return res.status(429).json({
        success: false,
        message: "Maximum OTP attempts reached. Request a new OTP."
      });
    }

    return res.status(400).json({
      success: false,
      message: "Incorrect OTP.",
      attemptsRemaining: MAX_OTP_ATTEMPTS - result.challenge.attempts
    });
  }

  result.challenge.used = true;
  challenges.delete(challengeId);

  const user = [...users.values()].find((u) => u.id === result.challenge.userId);
  user.emailVerified = true;

  res.json({
    success: true,
    message: "Email verified. Continue with SMS verification.",
    userId: user.id
  });
});

app.post("/api/send-sms-otp", (req, res) => {
  const { userId } = req.body;
  const user = [...users.values()].find((u) => u.id === userId);

  if (!user || !user.emailVerified) {
    return res.status(400).json({
      success: false,
      message: "Email verification is required first."
    });
  }

  const challenge = createChallenge(user.id, "sms", "registration-sms");

  res.json({
    success: true,
    message: "A simulated SMS OTP was generated.",
    challengeId: challenge.challengeId,
    method: "sms"
  });
});

app.post("/api/verify-sms-otp", (req, res) => {
  const { userId, challengeId, otp } = req.body;
  const result = validateChallenge(challengeId, userId, "registration-sms");

  if (!result.ok) {
    return res.status(result.status).json({
      success: false,
      message: result.message
    });
  }

  result.challenge.attempts += 1;

  if (hashOtp(otp) !== result.challenge.otpHash) {
    if (result.challenge.attempts >= MAX_OTP_ATTEMPTS) {
      challenges.delete(challengeId);
      return res.status(429).json({
        success: false,
        message: "Maximum OTP attempts reached. Request a new OTP."
      });
    }

    return res.status(400).json({
      success: false,
      message: "Incorrect OTP.",
      attemptsRemaining: MAX_OTP_ATTEMPTS - result.challenge.attempts
    });
  }

  result.challenge.used = true;
  challenges.delete(challengeId);

  const user = [...users.values()].find((u) => u.id === userId);
  user.smsVerified = true;
  user.mfaEnabled = true;

  res.json({
    success: true,
    message: "MFA enabled. Registration completed.",
    mfaEnabled: true,
    user: safeUser(user)
  });
});

// ---------- Login + MFA ----------

app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const rememberMe = Boolean(req.body.rememberMe);

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required."
      });
    }

    const lock = getLockInfo(email);

    if (lock.locked) {
      const seconds = Math.ceil((lock.lockedUntil - Date.now()) / 1000);
      return res.status(423).json({
        success: false,
        locked: true,
        message: `Account temporarily locked. Try again in ${seconds} seconds.`
      });
    }

    const user = users.get(email);

    if (!user) {
      recordLoginFailure(email);
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const passwordValid = await bcrypt.compare(password, user.passwordHash);

    if (!passwordValid) {
      const failure = recordLoginFailure(email);

      if (failure.locked) {
        return res.status(423).json({
          success: false,
          locked: true,
          message: "Too many failed attempts. Account temporarily locked."
        });
      }

      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
        attemptsRemaining: MAX_LOGIN_FAILURES - failure.failures
      });
    }

    clearLoginFailures(email);

    if (!user.mfaEnabled) {
      return res.status(403).json({
        success: false,
        mfaRequired: false,
        message: "MFA is not enabled for this account. Complete registration first."
      });
    }

    const challenge = createChallenge(user.id, "email", "login");

    req.session.pendingMfaUserId = user.id;
    req.session.pendingChallengeId = challenge.challengeId;

    if (rememberMe) {
      req.session.rememberMe = true;
    }

    res.json({
      success: true,
      mfaRequired: true,
      method: "email",
      challengeId: challenge.challengeId,
      message: "Credentials valid. Verify the MFA OTP."
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.post("/api/verify-login-otp", (req, res) => {
  const { challengeId, otp } = req.body;
  const userId = req.session.pendingMfaUserId;

  if (!userId || req.session.pendingChallengeId !== challengeId) {
    return res.status(401).json({
      success: false,
      message: "Login MFA session is invalid. Please log in again."
    });
  }

  const result = validateChallenge(challengeId, userId, "login");

  if (!result.ok) {
    return res.status(result.status).json({
      success: false,
      message: result.message
    });
  }

  result.challenge.attempts += 1;

  if (hashOtp(otp) !== result.challenge.otpHash) {
    if (result.challenge.attempts >= MAX_OTP_ATTEMPTS) {
      challenges.delete(challengeId);
      req.session.destroy(() => {});
      return res.status(429).json({
        success: false,
        locked: true,
        message: "Maximum OTP attempts reached. Please log in again."
      });
    }

    return res.status(400).json({
      success: false,
      message: "Incorrect OTP.",
      attemptsRemaining: MAX_OTP_ATTEMPTS - result.challenge.attempts
    });
  }

  result.challenge.used = true;
  challenges.delete(challengeId);

  req.session.userId = userId;
  delete req.session.pendingMfaUserId;
  delete req.session.pendingChallengeId;

  if (req.session.rememberMe) {
    req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30;
  }

  const user = [...users.values()].find((u) => u.id === userId);

  req.session.save((error) => {
    if (error) {
      console.error(error);
      return res.status(500).json({
        success: false,
        message: "Could not create authenticated session."
      });
    }

    res.json({
      success: true,
      message: "Login successful.",
      user: safeUser(user)
    });
  });
});

// ---------- Session authentication ----------

function requireSession(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message: "Authentication required."
    });
  }

  next();
}

app.get("/api/me", requireSession, (req, res) => {
  const user = [...users.values()].find((u) => u.id === req.session.userId);

  if (!user) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message: "User session is no longer valid."
    });
  }

  res.json({
    success: true,
    authenticated: true,
    user: safeUser(user),
    authentication: "server-side session + MFA"
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        success: false,
        message: "Logout failed."
      });
    }

    res.clearCookie("secureid.sid", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    });

    res.json({
      success: true,
      message: "Logged out successfully."
    });
  });
});

// ---------- JWT authentication ----------

app.post("/api/token", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const user = users.get(email);

  if (!user || !user.mfaEnabled) {
    return res.status(401).json({
      success: false,
      message: "Valid MFA-enabled credentials are required."
    });
  }

  bcrypt.compare(password, user.passwordHash).then((valid) => {
    if (!valid) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials."
      });
    }

    const token = jwt.sign(
      {
        sub: user.id,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: "15m", issuer: "secureid" }
    );

    res.json({
      success: true,
      tokenType: "Bearer",
      expiresIn: 900,
      token
    });
  });
});

function requireJwt(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Bearer token required."
    });
  }

  const token = header.slice(7);

  try {
    req.jwtPayload = jwt.verify(token, JWT_SECRET, {
      issuer: "secureid"
    });
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired JWT."
    });
  }
}

app.get("/api/protected", requireJwt, (req, res) => {
  res.json({
    success: true,
    message: "JWT validated. You can access this protected API.",
    claims: req.jwtPayload
  });
});

// ---------- Static frontend ----------

app.use(express.static(path.join(__dirname, "..", "public")));

app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`SecureID running at http://localhost:${PORT}`);
  });
}

module.exports = app;
