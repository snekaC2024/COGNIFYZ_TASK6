const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
const db = require("./config/db");
require("dotenv").config();

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");

// Session Middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Passport Strategy for Authentication
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const [users] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
      if (users.length === 0) return done(null, false, { message: "User not found" });

      const user = users[0];
      const match = await bcrypt.compare(password, user.password);

      return match ? done(null, user) : done(null, false, { message: "Incorrect password" });
    } catch (error) {
      return done(error);
    }
  })
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const [users] = await db.query("SELECT * FROM users WHERE id = ?", [id]);
  done(null, users[0]);
});

// Authentication Middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => res.render("index"));

app.get("/dashboard", isAuthenticated, (req, res) => {
  res.send(`<h1>Welcome, ${req.user.username}!</h1><a href="/logout">Logout</a>`);
});

// Secure API Endpoint (Protected Route)
app.get("/secure-data", isAuthenticated, (req, res) => {
  res.json({ message: "This is protected data" });
});

// Authentication Routes
app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

// Register User
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword]);
    res.redirect("/login");
  } catch (error) {
    res.status(500).send("Error registering user");
  }
});

// Login User
app.post("/login", passport.authenticate("local", {
  successRedirect: "/dashboard",
  failureRedirect: "/login",
}));

// Logout User
app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/login");
  });
});

// Database Connection Test Route
app.get("/test-db", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT 1 + 1 AS result");
    res.json({ message: "Database Connected!", result: rows[0].result });
  } catch (error) {
    res.status(500).json({ error: "Database connection failed" });
  }
});

// Start Server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
