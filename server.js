// 🚀 TRVEL BACKEND — Google Auth + Email/Password
require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { OAuth2Client } = require("google-auth-library");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = process.env.JWT_SECRET || "travel_secret";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ✅ DATABASE POOL
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000,
});

// ✅ TEST CONNECTION
db.getConnection((err, connection) => {
  if (err) {
    console.error("❌ DB Connection Failed:", err);
  } else {
    console.log("✅ MySQL Connected");
    connection.release();
  }
});

// ✅ AUTO CREATE USERS TABLE (if not exists)
db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255),
    google_id VARCHAR(255),
    avatar VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) console.error("Table create error:", err);
  else console.log("✅ Users table ready");
});

// ================= EMAIL/PASSWORD AUTH =================

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    // Check if already exists
    db.query("SELECT id FROM users WHERE email=?", [email], async (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      if (result.length > 0)
        return res.status(409).json({ error: "Email already registered" });

      const hashed = await bcrypt.hash(password, 10);
      db.query(
        "INSERT INTO users (name, email, password) VALUES (?,?,?)",
        [name, email, hashed],
        (err, result) => {
          if (err) return res.status(500).json({ error: err.message });
          const token = jwt.sign({ id: result.insertId, email, name }, SECRET, { expiresIn: "7d" });
          res.json({ token, user: { id: result.insertId, name, email } });
        }
      );
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "All fields required" });

    db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      if (result.length === 0)
        return res.status(404).json({ error: "User not found" });

      const user = result[0];
      if (!user.password)
        return res.status(400).json({ error: "Please login with Google" });

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return res.status(401).json({ error: "Wrong password" });

      const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name },
        SECRET,
        { expiresIn: "7d" }
      );
      res.json({ token, user: { id: user.id, name: user.name, email: user.email, avatar: user.avatar } });
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GOOGLE AUTH =================

app.post("/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential)
      return res.status(400).json({ error: "No credential provided" });

    // Verify Google Token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: google_id, email, name, picture: avatar } = payload;

    // Check if user exists
    db.query("SELECT * FROM users WHERE email=?", [email], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      if (result.length > 0) {
        // User exists — update google_id & avatar if not set
        const user = result[0];
        db.query(
          "UPDATE users SET google_id=?, avatar=? WHERE email=?",
          [google_id, avatar, email]
        );
        const token = jwt.sign(
          { id: user.id, email: user.email, name: user.name },
          SECRET,
          { expiresIn: "7d" }
        );
        return res.json({
          token,
          user: { id: user.id, name: user.name, email: user.email, avatar },
        });
      }

      // New user — create account
      db.query(
        "INSERT INTO users (name, email, google_id, avatar) VALUES (?,?,?,?)",
        [name, email, google_id, avatar],
        (err, insertResult) => {
          if (err) return res.status(500).json({ error: err.message });
          const token = jwt.sign(
            { id: insertResult.insertId, email, name },
            SECRET,
            { expiresIn: "7d" }
          );
          res.json({
            token,
            user: { id: insertResult.insertId, name, email, avatar },
          });
        }
      );
    });
  } catch (err) {
    console.error("Google Auth Error:", err);
    res.status(401).json({ error: "Google verification failed" });
  }
});

// ================= MIDDLEWARE — Verify JWT =================

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token provided" });
  try {
    const token = auth.split(" ")[1];
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ================= PACKAGES =================

app.get("/packages", (req, res) => {
  const { search } = req.query;
  let query = "SELECT * FROM packages";
  db.query(query, search ? [`%${search}%`] : [], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result);
  });
});

app.post("/add-package", (req, res) => {
  const { title, price, image, description } = req.body;
  if (!title || !price) return res.status(400).json({ error: "Missing fields" });
  db.query(
    "INSERT INTO packages (title, price, image, description) VALUES (?,?,?,?)",
    [title, price, image, description],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Package Added ✅" });
    }
  );
});

// ================= BOOKING =================

app.post("/book", (req, res) => {
  const { name, email, package_id } = req.body;
  if (!name || !email || !package_id)
    return res.status(400).json({ error: "All fields required" });
  db.query(
    "INSERT INTO bookings (name, email, package_id) VALUES (?,?,?)",
    [name, email, package_id],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Booked ✅" });
    }
  );
});

// ================= SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});