// 🚀 FINAL CLEAN BACKEND (FIXED DB TIMEOUT + RAILWAY READY ✅)

require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = "travel_secret";

// ✅ FIXED DATABASE CONNECTION (POOL + PORT + TIMEOUT)
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

// ================= AUTH =================

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).send("All fields required");
    }

    const hashed = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users (name,email,password) VALUES (?,?,?)",
      [name, email, hashed],
      (err) => {
        if (err) return res.status(500).send(err);
        res.send("User Created ✅");
      }
    );
  } catch (err) {
    res.status(500).send(err);
  }
});

app.post("/login", (req, res) => {
  try {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
      if (err) return res.status(500).send(err);
      if (result.length === 0) return res.status(404).send("User not found");

      const valid = await bcrypt.compare(password, result[0].password);
      if (!valid) return res.status(401).send("Wrong password");

      const token = jwt.sign({ id: result[0].id }, SECRET);
      res.json({ token });
    });
  } catch (err) {
    res.status(500).send(err);
  }
});

// ================= PACKAGES =================

app.get("/packages", (req, res) => {
  const { search } = req.query;

  let query = "SELECT * FROM packages";

  if (search) {
    query = "SELECT * FROM packages WHERE title LIKE ?";
  }

  db.query(query, search ? [`%${search}%`] : [], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json(result);
  });
});

// ================= ADMIN =================

app.post("/add-package", (req, res) => {
  const { title, price, image, description } = req.body;

  if (!title || !price) {
    return res.status(400).send("Missing fields");
  }

  db.query(
    "INSERT INTO packages (title, price, image, description) VALUES (?,?,?,?)",
    [title, price, image, description],
    (err) => {
      if (err) return res.status(500).send(err);
      res.send("Package Added ✅");
    }
  );
});

// ================= BOOKING =================

app.post("/book", (req, res) => {
  const { name, email, package_id } = req.body;

  if (!name || !email || !package_id) {
    return res.status(400).send("All fields required");
  }

  db.query(
    "INSERT INTO bookings (name,email,package_id) VALUES (?,?,?)",
    [name, email, package_id],
    (err) => {
      if (err) return res.status(500).send(err);
      res.send("Booked ✅");
    }
  );
});

// ================= SERVER =================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});


// 🎯 FIXES APPLIED:
// ✅ Railway timeout fix
// ✅ Pool connection (stable)
// ✅ Port added
// ✅ Production ready
