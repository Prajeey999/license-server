require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// ======================================================
// MIDDLEWARE CONFIGURATION
// ======================================================
app.use(cors({
  origin: "*", 
  allowedHeaders: ["Content-Type", "Authorization", "ngrok-skip-browser-warning"]
}));
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// --- HELPER: Parse Duration ---
const getDurationMs = (durationStr) => {
  let defaultMs = 30 * 24 * 60 * 60 * 1000;
  if (!durationStr || durationStr.toLowerCase() === "null") return defaultMs;

  const match = durationStr.match(/(\d+)\s*(day|hour|minute|second)/i);
  if (!match) return defaultMs;

  const value = parseInt(match[1]);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case "day": return value * 24 * 60 * 60 * 1000;
    case "hour": return value * 60 * 60 * 1000;
    case "minute": return value * 60 * 1000;
    case "second": return value * 1000;
    default: return defaultMs;
  }
};

// ======================================================
// VERIFY LICENSE + ISSUE JWT (Modified for Stability)
// ======================================================
app.post("/verify", async (req, res) => {
  const { email, license_key } = req.body;

  if (!email || !license_key) {
    return res.status(400).json({ success: false, message: "Missing email or license key" });
  }

  try {
    const { data: license, error } = await supabase
      .from("licenses")
      .select("*")
      .eq("email", email)
      .eq("license_key", license_key)
      .single();

    if (error || !license) {
      return res.status(404).json({ success: false, message: "Invalid credentials" });
    }

    if (license.status === "revoked" || license.status === "suspended") {
      return res.status(403).json({ success: false, message: "License revoked" });
    }

    const now = new Date();

    // Already activated logic
    if (license.is_used && license.expires_at) {
      const expiryDate = new Date(license.expires_at);

      if (expiryDate < now) {
        if (license.status !== "expired") {
          await supabase.from("licenses").update({ status: "expired" }).eq("id", license.id);
        }
        return res.status(403).json({ success: false, message: "License expired" });
      }

      // FIX: Set JWT to expire in 24h instead of the exact license expiry
      // This allows the /validate-token heartbeat to handle the "Expired" logic gracefully.
      const token = jwt.sign(
        { id: license.id, email: license.email },
        process.env.JWT_SECRET,
        { expiresIn: "24h" } 
      );

      return res.json({ success: true, token });
    }

    // First activation logic
    const durationMs = getDurationMs(license.plan_duration);
    const expiryTimestamp = new Date(now.getTime() + durationMs);

    const { data: activated, error: updateErr } = await supabase
      .from("licenses")
      .update({
        is_used: true,
        expires_at: expiryTimestamp.toISOString(),
        status: "active"
      })
      .eq("id", license.id)
      .select()
      .single();

    if (updateErr) throw updateErr;

    // FIX: Set JWT to expire in 24h
    const token = jwt.sign(
      { id: activated.id, email: activated.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    return res.json({ success: true, token });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ======================================================
// VALIDATE TOKEN (The Heartbeat Check)
// ======================================================
app.get("/validate-token", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ valid: false, reason: "NO_TOKEN" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Fetch fresh status from Supabase to check the REAL database state
    const { data: license, error } = await supabase
      .from("licenses")
      .select("id, status, expires_at")
      .eq("id", decoded.id)
      .single();

    if (error || !license) {
      return res.status(401).json({ valid: false, reason: "NOT_FOUND" });
    }

    const now = new Date();
    const expiry = new Date(license.expires_at);

    // 1. Check for Revoked/Suspended
    if (license.status === "revoked" || license.status === "suspended") {
      return res.status(403).json({ valid: false, reason: "REVOKED" });
    }

    // 2. Check for Expiration (Database is the source of truth)
    if (expiry < now || license.status === "expired") {
      if (license.status !== "expired") {
        await supabase.from("licenses").update({ status: "expired" }).eq("id", license.id);
      }
      return res.status(401).json({ valid: false, reason: "EXPIRED" });
    }

    // Success: Token is signed correctly AND database says license is active
    res.json({ valid: true });

  } catch (err) {
    // This triggers if the 24h JWT has expired or the secret key is wrong
    return res.status(401).json({ valid: false, reason: "INVALID_SESSION" });
  }
});

// ======================================================
// GENERATE LICENSE (Kept exactly as you had it)
// ======================================================
app.post("/generate", async (req, res) => {
  const { email, plan_duration, admin_secret } = req.body;

  if (admin_secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  if (!email) {
    return res.status(400).json({ success: false, message: "Email required" });
  }

  const part1 = Math.random().toString(36).substring(2, 6).toUpperCase();
  const part2 = Math.random().toString(36).substring(2, 6).toUpperCase();
  const key = `PRO-${part1}-${part2}`;

  const { data, error } = await supabase
    .from("licenses")
    .insert([{
      email,
      license_key: key,
      plan_duration: plan_duration || "30 days",
      status: "active",
      is_used: false,
      created_at: new Date().toISOString()
    }])
    .select()
    .single();

  if (error) {
    return res.status(500).json({ success: false, error: error.message });
  }

  res.json({ success: true, license: data });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 License Server running on port ${PORT}`));