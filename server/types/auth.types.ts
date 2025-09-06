// Shared types for JWT authentication across the application

export interface JwtPayload {
  _id: string;
  role: 'admin' | 'faculty' | 'student';
  iat?: number;
  exp?: number;
}

export interface AuthenticatedRequest {
  _id: string;
  role: string;
}
