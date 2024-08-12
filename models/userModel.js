const validator = require("validator");

const userScheme = {
  name: {
    type: "TEXT",
    required: [true, "Please fill your name"],
  },
  email: {
    type: "TEXT",
    required: [true, "Please fill your email"],
    unique: true,
    lowercase: true,
    validate: (email) => validator.isEmail(email),
  },
  address: {
    type: "TEXT",
    trim: true,
  },
  password: {
    type: "TEXT",
    required: [true, "Please fill your password"],
    minLength: 6,
    select: false,
  },
  role: {
    type: "TEXT",
    enum: ["admin", "user"],
    default: "user",
  },
  active: {
    type: "BOOLEAN",
    default: true,
    select: false,
  },
};

module.exports = userScheme;
