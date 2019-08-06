const mongoose = require("mongoose");
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

mongoose.connect('mongodb://localhost:27017/auth_jwt', { useNewUrlParser: true });

// modelo
const userSchema = mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

// hashes the password
userSchema.pre("save", function (next) {
  bcrypt.hash(this.password, 10, (err, hash) => {
    if (err) {
      return next(err);
    }
    this.password = hash;
    next();
  });
});

// used for authentication
userSchema.statics.authenticate = async (email, password) => {
  const user = await mongoose.model("User").findOne({ email: email });
  if (user) {
    return new Promise((resolve, reject) => {
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) reject(err);
        resolve(result === true ? user : null);
      });
    });
    return user;
  }

  return null;
};

const User = mongoose.model("User", userSchema);

const app = express();

// middlewares
app.use(express.json());

const requireUser = async (req, res, next) => {
  const token = req.get("Authorization");
  if (token) {
    try {
      console.log("Token: ", token);
      const decoded = await jwt.verify(token, process.env.SECRET_KEY || "secret key");
      console.log("Decoded: ", decoded);
      if (decoded.userId) {
        const user = await User.findOne({ _id: decoded.userId });
        if (user) {
          res.locals.user = user;
          return next();
        }
      } else {
        res.status(401).json({ error: "Invalid authorization token" });
      }
    } catch (e) {
      console.log(e);
      res.status(401).json({ error: "Invalid authorization token" });
    }
  } else {
    res.status(401).json({ error: "Not authorized" });
  }
};

app.post("/register", async (req, res, next) => {
  try {
    const user = await User.create({ email: req.body.email, password: req.body.password });

    const token = jwt.sign({ userId: user._id }, process.env.SECRET || "secret key");
    res.json({ token });
  } catch (err) {
    next(err);
  }
});

app.post("/login", async (req, res, next) => {
  try {
    const user = await User.authenticate(req.body.email, req.body.password);
    if (user) {
      const token = jwt.sign({ userId: user._id }, process.env.SECRET || "secret key");
      res.json({ token });
    } else {
      res.status(401).json({ error: "User or password is invalid" });
    }
  } catch (err) {
    next(err);
  }
});

app.get("/properties", requireUser, async (req, res, next) => {
  try {
    console.log(res.locals.user);
    res.json([]);
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message });
});

app.listen(3000, () => console.log("Escuchando en el puerto 3000 ...."));
