import { ApiError } from '../../../rest-api/src/utils/ApiError';

describe('ApiError', () => {
  describe('constructor', () => {
    it('should create error with message and status code', () => {
      // Act
      const error = new ApiError(400, 'Bad request');

      // Assert
      expect(error.message).toBe('Bad request');
      expect(error.statusCode).toBe(400);
      expect(error.name).toBe('ApiError');
      expect(error.stack).toBeDefined();
    });

    it('should create error with additional details', () => {
      // Arrange
      const details = { field: 'email', issue: 'invalid format' };

      // Act
      const error = new ApiError(400, 'Validation error', details);

      // Assert
      expect(error.message).toBe('Validation error');
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual(details);
    });
  });

  describe('static factory methods', () => {
    it('should create badRequest error', () => {
      // Act
      const error = ApiError.badRequest('Invalid input');

      // Assert
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Invalid input');
    });

    it('should create unauthorized error', () => {
      // Act
      const error = ApiError.unauthorized('Token required');

      // Assert
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Token required');
    });

    it('should create forbidden error', () => {
      // Act
      const error = ApiError.forbidden('Access denied');

      // Assert
      expect(error.statusCode).toBe(403);
      expect(error.message).toBe('Access denied');
    });

    it('should create notFound error', () => {
      // Act
      const error = ApiError.notFound('Resource not found');

      // Assert
      expect(error.statusCode).toBe(404);
      expect(error.message).toBe('Resource not found');
    });

    it('should create conflict error', () => {
      // Act
      const error = ApiError.conflict('Resource already exists');

      // Assert
      expect(error.statusCode).toBe(409);
      expect(error.message).toBe('Resource already exists');
    });

    it('should create unprocessableEntity error', () => {
      // Act
      const error = ApiError.unprocessableEntity('Cannot process');

      // Assert
      expect(error.statusCode).toBe(422);
      expect(error.message).toBe('Cannot process');
    });

    it('should create internal error', () => {
      // Act
      const error = ApiError.internal('Server error');

      // Assert
      expect(error.statusCode).toBe(500);
      expect(error.message).toBe('Server error');
    });
  });

  describe('validation error', () => {
    it('should create validation error with field details', () => {
      // Arrange
      const validationErrors = [
        { field: 'email', message: 'Invalid email format' },
        { field: 'password', message: 'Password too weak' }
      ];

      // Act
      const error = ApiError.validation('Validation failed', validationErrors);

      // Assert
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Validation failed');
      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.details).toEqual(validationErrors);
    });

    it('should create validation error with default message', () => {
      // Act
      const error = ApiError.validation();

      // Assert
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Validation failed');
      expect(error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('error serialization', () => {
    it('should serialize to JSON correctly', () => {
      // Arrange
      const error = new ApiError(400, 'Test error', { field: 'test' });

      // Act
      const serialized = JSON.parse(JSON.stringify(error));

      // Assert
      expect(serialized).toEqual({
        name: 'ApiError',
        message: 'Test error',
        statusCode: 400,
        details: { field: 'test' }
      });
    });

    it('should serialize validation error correctly', () => {
      // Arrange
      const validationErrors = [{ field: 'email', message: 'Required' }];
      const error = ApiError.validation('Failed', validationErrors);

      // Act
      const serialized = JSON.parse(JSON.stringify(error));

      // Assert
      expect(serialized).toEqual({
        name: 'ApiError',
        message: 'Failed',
        statusCode: 400,
        code: 'VALIDATION_ERROR',
        details: validationErrors
      });
    });
  });

  describe('inheritance', () => {
    it('should be instance of Error', () => {
      // Act
      const error = new ApiError(400, 'Test');

      // Assert
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(ApiError);
    });

    it('should have correct prototype chain', () => {
      // Act
      const error = new ApiError(400, 'Test');

      // Assert
      expect(Object.getPrototypeOf(error)).toBe(ApiError.prototype);
      expect(Object.getPrototypeOf(ApiError.prototype)).toBe(Error.prototype);
    });
  });

  describe('edge cases', () => {
    it('should handle undefined message', () => {
      // Act
      const error = new ApiError(500, undefined as any);

      // Assert
      expect(error.message).toBe('undefined');
      expect(error.statusCode).toBe(500);
    });

    it('should handle null details', () => {
      // Act
      const error = new ApiError(400, 'Test', null as any);

      // Assert
      expect(error.details).toBeNull();
    });

    it('should handle zero status code', () => {
      // Act
      const error = new ApiError(0, 'Test');

      // Assert
      expect(error.statusCode).toBe(0);
    });

    it('should handle negative status code', () => {
      // Act
      const error = new ApiError(-1, 'Test');

      // Assert
      expect(error.statusCode).toBe(-1);
    });
  });
});