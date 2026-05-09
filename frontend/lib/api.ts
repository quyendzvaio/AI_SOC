export type User = {
  id: string;
  email: string;
  role: string;
  is_email_verified: boolean;
};

export type AuthOut = {
  token: string | null;
  user: User;
  otp_required: boolean;
};

export type LogItem = {
  id: string;
  source_type: "windows_agent" | "ubuntu_agent" | "email" | "webhook";
  source: string;
  log_summary: string;
  extracted_entities: Record<string, unknown>;
  correlation_id: string;
  received_at: string;
};

export type AlertItem = {
  id: string;
  log_id: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  status: string;
  message: string;
  ai_summary: string;
  rule_name: string | null;
  detected_at: string;
};

export type NotificationItem = {
  id: string;
  alert_id: string;
  channel: string;
  recipient: string;
  status: string;
  created_at: string;
};

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || response.statusText);
  }
  return response.json() as Promise<T>;
}

export function register(email: string, password: string) {
  return request<AuthOut>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export function verifyOtp(email: string, otp: string) {
  return request<AuthOut>("/auth/verify-otp", {
    method: "POST",
    body: JSON.stringify({ email, otp, purpose: "register" }),
  });
}

export function login(email: string, password: string) {
  return request<AuthOut>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export function authed<T>(path: string, token: string) {
  return request<T>(path, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export function streamUrl(token: string) {
  return `${API_BASE_URL}/stream/events?token=${encodeURIComponent(token)}`;
}
