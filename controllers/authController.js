const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const AppError = require("../utils/api/appError");
const pool = require("../database/connectdb");

const User = require("../models/userModel");
const { insertData, createTable } = require("../utils/api/functions");

const createToken = (id) => {
  return jwt.sign(
    {
      id,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN,
    }
  );
};

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!pool) {
      return next(new AppError(500, "fail", "database not connected"));
    }
    console.log("req: ", req.headers);
    if (
      req.headers["user-agent"].startsWith("Mozilla") &&
      req.headers["user-agent"].includes("AppleWebKit")
    ) {
      res.cookie("user_id", 12345, { maxAge: 900000, httpOnly: true }); // Set a cookie
      if (email && password) {
        const getPassword = `SELECT * FROM dark.users WHERE email = $1`;

        const user = await pool.query(getPassword, [email]);

        const isValidPassword = bcrypt.compareSync(
          password,
          user.rows[0].password
        );
        res.cookie("user", email);
        if (isValidPassword) {
          res.status(200).json({
            message: `1 user found with email ${email}`,
            token: createToken(user.rows[0].id),
            status: "success",
            statusCode: 200,
            cookies: req.cookies,
          });
        } else {
          res
            .status(200)
            .json(
              new AppError(
                "404",
                "failed",
                `user with email ${email} does not exists.`
              )
            );
        }
      } else {
        return next(
          new AppError(404, "fail", "Please provide email or password"),
          req,
          res,
          next
        );
      }
    } else {
      res.status(500).json({
        ...new AppError(
          "500",
          "failed",
          "you must call api from web interface only."
        ),
        message: "you must call api from web interface only.",
      });
    }
  } catch (error) {
    next(error);
  }
};

exports.signup = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (User.email.validate(email) && req.body.password) {
      const validateField = `SELECT EXISTS (
          SELECT 1
          FROM dark.users
          WHERE email = $1
      )`;

      const validateTable = await pool.query(`SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE  table_schema = 'dark'
        AND    table_name   = 'users'
        );`);

      const hashPassword = bcrypt.hashSync(password, process.env.SALT);

      if (!validateTable.rows[0].exists) {
        try {
          createTable(pool, User, "users");
          insertData(
            pool,
            ["email", "password"],
            [email, hashPassword],
            "users"
          ).then((data) => {
            res.status(201).json({
              status: "success",
              code: 201,
              message: `user created with ${email}.`,
            });
          });
          res.status(201).json({
            status: "success",
            code: 201,
            message: `user created with ${email}.`,
          });
        } catch (error) {
          next(error);
        }
      } else {
        const isEmailExits = await pool.query(validateField, [email]);
        console.log(isEmailExits);
        if (isEmailExits.rows[0].exists) {
          res.status(200).json({
            status: "success",
            code: 200,
            message: "user with this email already exists.",
          });
        } else {
          insertData(
            pool,
            ["email", "password"],
            [email, hashPassword],
            "users"
          ).then((data) => {
            res.status(201).json({
              status: "success",
              code: 201,
              message: `user created with ${email}.`,
            });
          });
        }
      }
    } else {
      res.status(400).json({
        status: "failed",
        code: 400,
        message: "request body is missing one or more parameter",
      });
    }
  } catch (err) {
    next(err);
  }
};

exports.protect = async (req, res, next) => {
  try {
    // 1) check if the token is there
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }
    if (!token) {
      return next(
        new AppError(
          401,
          "fail",
          "You are not logged in! Please login in to continue"
        ),
        req,
        res,
        next
      );
    }

    // 2) Verify token
    const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3) check if the user is exist (not deleted)
    const user = await User.findById(decode.id);
    if (!user) {
      return next(
        new AppError(401, "fail", "This user is no longer exist"),
        req,
        res,
        next
      );
    }

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
};

// Authorization check if the user have rights to do this action
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError(403, "fail", "You are not allowed to do this action"),
        req,
        res,
        next
      );
    }
    next();
  };
};
