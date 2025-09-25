import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { authMiddleware, optionalAuth, requireRole, AuthenticatedRequest } from '../../../rest-api/src/middleware/auth';
import { ApiError } from '../../../rest-api/src/utils/ApiError';

// Mock jwt
jest.mock('jsonwebtoken');
const mockJwt = jwt as jest.Mocked<typeof jwt>;

// Mock config
jest.mock('../../../rest-api/src/config/environment', () => ({
  config: {
    jwt: {
      secret: 'test-secret'
    }
  }
}));

describe('Auth Middleware', () => {
  let mockRequest: Partial<AuthenticatedRequest>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction;

  beforeEach(() => {
    mockRequest = {
      headers: {}
    };
    mockResponse = {};
    nextFunction = jest.fn();
    jest.clearAllMocks();
  });

  describe('authMiddleware', () => {
    it('should authenticate valid token', () => {
      // Arrange
      const mockPayload = {
        id: 'user-123',
        email: 'test@example.com',
        role: 'user'
      };
      mockRequest.headers = {
        authorization: 'Bearer valid-token'
      };
      mockJwt.verify.mockReturnValue(mockPayload as any);

      // Act
      authMiddleware(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(mockJwt.verify).toHaveBeenCalledWith('valid-token', 'test-secret');
      expect(mockRequest.user).toEqual(mockPayload);
      expect(nextFunction).toHaveBeenCalledWith();
    });

    it('should reject request without token', () => {
      // Arrange
      mockRequest.headers = {};

      // Act
      authMiddleware(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(nextFunction).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (nextFunction as jest.Mock).mock.calls[0][0];
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Access token required');
    });

    it('should reject malformed authorization header', () => {
      // Arrange
      mockRequest.headers = {
        authorization: 'InvalidFormat token'
      };

      // Act
      authMiddleware(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(nextFunction).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (nextFunction as jest.Mock).mock.calls[0][0];
      expect(error.statusCode).toBe(401);
    });

    it('should handle JWT verification errors', () => {
      // Arrange
      mockRequest.headers = {
        authorization: 'Bearer invalid-token'
      };
      mockJwt.verify.mockImplementation(() => {
        throw new jwt.JsonWebTokenError('Invalid token');
      });

      // Act
      authMiddleware(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(nextFunction).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (nextFunction as jest.Mock).mock.calls[0][0];
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Invalid token');
    });

    it('should handle expired tokens', () => {
      // Arrange
      mockRequest.headers = {
        authorization: 'Bearer expired-token'
      };
      mockJwt.verify.mockImplementation(() => {
        throw new jwt.TokenExpiredError('Token expired', new Date());
      });

      // Act
      authMiddleware(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(nextFunction).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (nextFunction as jest.Mock).mock.calls[0][0];
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Token expired');
    });
  });

  describe('optionalAuth', () => {
    it('should authenticate when valid token provided', () => {
      // Arrange
      const mockPayload = {
        id: 'user-123',
        email: 'test@example.com',
        role: 'user'
      };
      mockRequest.headers = {
        authorization: 'Bearer valid-token'
      };
      mockJwt.verify.mockReturnValue(mockPayload as any);

      // Act
      optionalAuth(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(mockRequest.user).toEqual(mockPayload);
      expect(nextFunction).toHaveBeenCalledWith();
    });

    it('should continue without authentication when no token provided', () => {
      // Arrange
      mockRequest.headers = {};

      // Act
      optionalAuth(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(mockRequest.user).toBeUndefined();
      expect(nextFunction).toHaveBeenCalledWith();
    });

    it('should continue without authentication when invalid token provided', () => {
      // Arrange
      mockRequest.headers = {
        authorization: 'Bearer invalid-token'
      };
      mockJwt.verify.mockImplementation(() => {
        throw new jwt.JsonWebTokenError('Invalid token');
      });

      // Act
      optionalAuth(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(mockRequest.user).toBeUndefined();
      expect(nextFunction).toHaveBeenCalledWith();
    });
  });

  describe('requireRole', () => {
    it('should allow access with correct role', () => {
      // Arrange
      const middleware = requireRole(['admin', 'user']);
      mockRequest.user = {
        id: 'user-123',
        email: 'test@example.com',
        role: 'admin'
      };

      // Act
      middleware(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(nextFunction).toHaveBeenCalledWith();
    });

    it('should deny access with incorrect role', () => {
      // Arrange
      const middleware = requireRole(['admin']);
      mockRequest.user = {
        id: 'user-123',
        email: 'test@example.com',
        role: 'user'
      };

      // Act
      middleware(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(nextFunction).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (nextFunction as jest.Mock).mock.calls[0][0];
      expect(error.statusCode).toBe(403);
      expect(error.message).toBe('Insufficient permissions');
    });

    it('should deny access when user not authenticated', () => {
      // Arrange
      const middleware = requireRole(['admin']);
      mockRequest.user = undefined;

      // Act
      middleware(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

      // Assert
      expect(nextFunction).toHaveBeenCalledWith(expect.any(ApiError));
      const error = (nextFunction as jest.Mock).mock.calls[0][0];
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Authentication required');
    });
  });
});