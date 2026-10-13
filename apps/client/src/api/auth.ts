import { apiRequest } from "./client";

export interface User {
  id: string;
  email: string;
  nickname: string;
  avatar_url: string;
  status_text: string;
  created_at: string;
}

export interface AuthResult {
  access_token: string;
  refresh_token: string;
  expires_at: number;
  user: User;
}

export interface RegisterInput {
  email: string;
  code: string;
  password: string;
  nickname: string;
}

export function sendRegisterCode(email: string): Promise<{ message: string }> {
  return apiRequest("/api/v1/auth/register/send-code", {
    method: "POST",
    body: { email },
  });
}

export function register(input: RegisterInput): Promise<AuthResult> {
  return apiRequest("/api/v1/auth/register", { method: "POST", body: input });
}

export function login(email: string, password: string): Promise<AuthResult> {
  return apiRequest("/api/v1/auth/login", {
    method: "POST",
    body: { email, password },
  });
}

export function fetchMe(): Promise<{ user: User }> {
  return apiRequest("/api/v1/me", { auth: true });
}

export function logout(refreshToken: string): Promise<unknown> {
  return apiRequest("/api/v1/auth/logout", {
    method: "POST",
    body: { refresh_token: refreshToken },
  });
}
