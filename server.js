const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

const db = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    rejectUnauthorized: false,
  },
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.get("/", (req, res) => {
  res.send("NovaWeb Backend Running");
});

app.get("/api/test-env", (req, res) => {
  res.json({
    jwt: process.env.JWT_SECRET ? "JWT found" : "JWT missing",
  });
});

app.get("/api/test-db", async (req, res) => {
  try {
    const result = await db.query("SELECT NOW()");
    res.json({
      message: "PostgreSQL connected successfully",
      time: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({
      message: "PostgreSQL connection failed",
      error: err.message,
    });
  }
});

app.get("/api/test-email", async (req, res) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: "NovaWeb Test Email",
      text: "Email system working successfully",
    });

    res.json({ message: "Test email sent successfully" });
  } catch (err) {
    res.status(500).json({
      message: "Email sending failed",
      error: err.message,
    });
  }
});

// Admin login
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const cleanEmail = email.trim().toLowerCase();

    const result = await db.query(
      "SELECT * FROM admin_users WHERE LOWER(email) = $1 AND password = $2",
      [cleanEmail, password]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const admin = result.rows[0];

    const token = jwt.sign(
      { id: admin.id, email: admin.email, role: "admin" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

// Customer Register
app.post("/api/customer/register", async (req, res) => {
  try {
    let { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    name = name.trim();
    email = email.trim().toLowerCase();

    const existingUser = await db.query(
      "SELECT * FROM customer_users WHERE LOWER(email) = $1",
      [email]
    );

    if (existingUser.rows.length > 0 && existingUser.rows[0].is_verified) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    if (existingUser.rows.length > 0 && !existingUser.rows[0].is_verified) {
      await db.query(
        `UPDATE customer_users
         SET name = $1, password = $2, otp = $3
         WHERE LOWER(email) = $4`,
        [name, hashedPassword, otp, email]
      );
    } else {
      await db.query(
        `INSERT INTO customer_users
         (name, email, password, otp, is_verified)
         VALUES ($1, $2, $3, $4, false)`,
        [name, email, hashedPassword, otp]
      );
    }

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "NovaWeb Developer - OTP Verification",
      html: `
        <div style="font-family: Arial; padding: 20px;">
          <h2>NovaWeb Developer</h2>
          <p>Your verification OTP is:</p>
          <h1 style="color:#2563eb;">${otp}</h1>
          <p>Enter this OTP to verify your account.</p>
        </div>
      `,
    });

    res.status(201).json({ message: "OTP sent to your email." });
  } catch (err) {
    console.log("Register error:", err.message);

    res.status(500).json({
      message: "Registration failed",
      error: err.message,
    });
  }
});

// Verify OTP
app.post("/api/customer/verify-otp", async (req, res) => {
  try {
    let { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: "Email and OTP are required" });
    }

    email = email.trim().toLowerCase();
    otp = otp.trim();

    const result = await db.query(
      "SELECT * FROM customer_users WHERE LOWER(email) = $1 AND otp = $2",
      [email, otp]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    await db.query(
      `UPDATE customer_users
       SET is_verified = true, otp = null
       WHERE LOWER(email) = $1`,
      [email]
    );

    res.json({ message: "Email verified successfully" });
  } catch (err) {
    res.status(500).json({
      message: "OTP verification failed",
      error: err.message,
    });
  }
});

// Customer Login
app.post("/api/customer/login", async (req, res) => {
  try {
    let { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    email = email.trim().toLowerCase();

    const result = await db.query(
      "SELECT * FROM customer_users WHERE LOWER(email) = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Email not found",
      });
    }

    const user = result.rows[0];

    console.log("Customer login attempt:", user.email);
    console.log("Verified:", user.is_verified);

    if (user.is_verified !== true) {
      return res.status(403).json({
        message: "Please verify your email first",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    console.log("Password match:", isMatch);

    if (!isMatch) {
      return res.status(401).json({
        message: "Wrong password",
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: "customer",
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.log("Customer login backend error:", err.message);

    res.status(500).json({
      message: "Login failed",
      error: err.message,
    });
  }
});

// Customer starts chat
app.post("/api/chat/start", async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;

    if (!name || !message) {
      return res.status(400).json({ message: "Name and message required" });
    }

    const customerResult = await db.query(
      "INSERT INTO customers (name, email, phone) VALUES ($1, $2, $3) RETURNING *",
      [name, email, phone]
    );

    const customer = customerResult.rows[0];

    const messageResult = await db.query(
      "INSERT INTO chat_messages (customer_id, sender, message) VALUES ($1, $2, $3) RETURNING *",
      [customer.id, "customer", message]
    );

    res.status(201).json({
      message: "Chat started successfully",
      customer,
      chatMessage: messageResult.rows[0],
    });
  } catch (err) {
    console.log("Chat start error:", err.message);

    res.status(500).json({
      message: "Chat failed",
      error: err.message,
    });
  }
});

// Customer sends next message
app.post("/api/chat/message", async (req, res) => {
  try {
    const { customer_id, message } = req.body;

    if (!customer_id || !message) {
      return res.status(400).json({
        message: "Customer ID and message required",
      });
    }

    const result = await db.query(
      "INSERT INTO chat_messages (customer_id, sender, message) VALUES ($1, $2, $3) RETURNING *",
      [customer_id, "customer", message]
    );

    res.status(201).json({ message: "Message sent", data: result.rows[0] });
  } catch (err) {
    console.log("Customer message error:", err.message);

    res.status(500).json({
      message: "Message failed",
      error: err.message,
    });
  }
});

// Get customer chat
app.get("/api/chat/:customerId", async (req, res) => {
  try {
    const { customerId } = req.params;

    const result = await db.query(
      "SELECT * FROM chat_messages WHERE customer_id = $1 ORDER BY created_at ASC",
      [customerId]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({
      message: "Failed to fetch chat",
      error: err.message,
    });
  }
});

// Admin gets all customers
app.get("/api/admin/customers", async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM customers ORDER BY created_at DESC"
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({
      message: "Failed to fetch customers",
      error: err.message,
    });
  }
});

// Admin gets selected customer chat
app.get("/api/admin/chat/:customerId", async (req, res) => {
  try {
    const { customerId } = req.params;

    const result = await db.query(
      "SELECT * FROM chat_messages WHERE customer_id = $1 ORDER BY created_at ASC",
      [customerId]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({
      message: "Failed to fetch messages",
      error: err.message,
    });
  }
});

// Admin reply
app.post("/api/admin/reply", async (req, res) => {
  try {
    const { customer_id, message } = req.body;

    if (!customer_id || !message) {
      return res.status(400).json({
        message: "Customer ID and message required",
      });
    }

    const result = await db.query(
      "INSERT INTO chat_messages (customer_id, sender, message) VALUES ($1, $2, $3) RETURNING *",
      [customer_id, "admin", message]
    );

    res.status(201).json({ message: "Reply sent", data: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: "Reply failed", error: err.message });
  }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});