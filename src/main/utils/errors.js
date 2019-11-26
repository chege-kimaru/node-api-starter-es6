// eslint-disable-next-line max-classes-per-file
class BaseError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

class OperationNotAllowedError extends BaseError {
  constructor(message) {
    super(message);
    this.message = message || 'Invalid operation';
  }
}

class AuthenticationError extends BaseError {
  constructor(message) {
    super(message);
    this.message = message || 'Authentication failed. Please try again';
  }
}

class AuthorizationError extends BaseError {
  constructor(message) {
    super(message);
    this.message = message || 'Authorization failed.';
  }
}

class ResourceNotFoundError extends BaseError {
  constructor(message) {
    super(message);
    this.message = message || 'Resource not found';
  }
}


module.exports = {
  OperationNotAllowedError,
  AuthenticationError,
  AuthorizationError,
  ResourceNotFoundError,
};
