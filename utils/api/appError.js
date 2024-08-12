class AppError extends Error {
  constructor(statusCode, status, message) {
    super(message);
    console.log(statusCode, status, message);
    this.statusCode = statusCode;
    this.status = status;
    this.message = message;
  }
}

module.exports = AppError;
