require("dotenv").config();
const express = require("express");
const rateLimit = require("express-rate-limit");
// const helmet = require("helmet");
const cors = require("cors");
const hpp = require("hpp");
const xss = require("xss-clean");
const cookieParser = require("cookie-parser");

const clc = require("cli-color");

// api routes
const userRouter = require("./routes/userRoutes");
const authRouter = require("./routes/authRoutes");

const globalErrHandler = require("./controllers/errorControllers");
const AppError = require("./utils/api/appError");

const app = express();

const db = require("./database/connectdb");

// Allow Cross-Origin requests
app.use(cors());

// cookies parser
app.use(cookieParser());

// Limit request from the same API
const limiter = rateLimit({
  max: 150,
  windowMs: 60 * 60 * 1000,
  message: "Too Many Request from this IP, please try again in an hour",
});

console.log(clc.blue("> rate limit: ", 150));
app.use("/api", limiter);

// Body parser, reading data from body into req.body
app.use(
  express.json({
    limit: "15kb",
  })
);
console.log(clc.blue("> body size: ", "15kb"));

// Data sanitization against XSS(clean user input from malicious HTML code)
app.use(xss());
console.log(clc.blue("> xss: ", "true"));

// Prevent parameter pollution
app.use(hpp());
console.log(clc.blue("> parameter pollution: ", "true"));

app.use("/api/users", userRouter);
app.use("/api/auth", authRouter);

// handle undefined Routes
app.use("*", (req, res, next) => {
  const err = new AppError(404, "fail", "undefined route");
  next(err, req, res, next);
});

app.use(globalErrHandler);

// connected to the database
db.connect((err, client) => {
  console.log(clc.yellowBright("connecting to the database...."));
  if (err) {
    console.log(clc.red("unable to connect to the database!"));
    console.log(clc.red("> database connected: ", false));
  }

  console.log(clc.green("> database connected: ", true));
});

module.exports = app;
