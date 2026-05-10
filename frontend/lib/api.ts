export type User = {
  id: string;
  email: string;
  role: string;
  is_email_verified: boolean;
  notification_email: string | null;
  is_notification_email_verified: boolean;
};

export type RuntimeConfig = {
  llm_base_url?: string | null;
  llm_model?: string | null;
  llm_api_key?: string | null;
  abuseipdb_api_key?: string | null;
  virustotal_api_key?: string | null;
  nvd_api_key?: string | null;
};

export type DeviceConsent = {
  granted: boolean;
  granted_at: string | null;
};

export type MonitoredEmail = {
  id: string | null;
  email: string | null;
  is_verified: boolean;
  provider: string;
  otp_required: boolean;
  dev_otp?: string | null;
  message?: string | null;
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

export type IncidentItem = {
  id: string;
  name: string;
  description: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  status: string;
  created_at: string;
};

export type ChatMessage = {
  id: string;
  question: string;
  answer: string;
  asked_at: string;
};

export type EmailMessage = {
  id: string;
  message_id: string;
  mailbox: string;
  sender: string;
  recipients: string[];
  subject: string;
  body_summary: string;
  attachment_metadata: unknown[];
  received_at: string;
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

export function verifyOtp(email: string, otp: string, purpose: "register" | "login" = "register") {
  return request<AuthOut>("/auth/verify-otp", {
    method: "POST",
    body: JSON.stringify({ email, otp, purpose }),
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

export function authedPost<T>(path: string, token: string, body: unknown) {
  return request<T>(path, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
}

export function authedPatch<T>(path: string, token: string, body: unknown) {
  return request<T>(path, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
}

export function streamUrl(token: string) {
  return `${API_BASE_URL}/stream/events?token=${encodeURIComponent(token)}`;
}

export function queryAssistant(token: string, question: string) {
  return authedPost<{ answer: string }>("/assistant/query", token, { question });
}

export function getChatHistory(token: string) {
  return authed<ChatMessage[]>("/assistant/history?limit=50", token);
}

export function getMe(token: string) {
  return authed<User>("/me", token);
}

export function getMonitoredEmailFeed(token: string, limit = 100) {
  return authed<EmailMessage[]>(`/emails/monitored?limit=${limit}`, token);
}

export type NotifEmailResponse = {
  notification_email: string | null;
  is_notification_email_verified: boolean;
  otp_required: boolean;
  dev_otp?: string;
  message: string;
};

export function requestNotificationEmail(token: string, email: string) {
  return authedPost<NotifEmailResponse>("/settings/notification-email", token, { notification_email: email });
}

export function verifyNotificationEmail(token: string, otp: string) {
  return authedPost<NotifEmailResponse>("/settings/notification-email/verify", token, { otp });
}

export function removeNotificationEmail(token: string) {
  return authedDelete<NotifEmailResponse>("/settings/notification-email", token);
}

export function authedDelete<T>(path: string, token: string) {
  return request<T>(path, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
}

export function getIncidents(token: string) {
  return authed<IncidentItem[]>("/incidents?limit=50", token);
}

export function getDeviceConsent(token: string) {
  return authed<DeviceConsent>("/settings/device-consent", token);
}

export function updateDeviceConsent(token: string, granted: boolean) {
  return authedPost<DeviceConsent>("/settings/device-consent", token, { granted });
}

export function getRuntimeConfig(token: string) {
  return authed<RuntimeConfig>("/settings/runtime-config", token);
}

export function saveRuntimeConfig(token: string, config: RuntimeConfig) {
  return authedPost<RuntimeConfig>("/settings/runtime-config", token, config);
}

export function requestMonitoredEmail(token: string, email: string) {
  return authedPost<MonitoredEmail>("/settings/monitored-email", token, { email });
}

export function verifyMonitoredEmail(token: string, email: string, otp: string) {
  return authedPost<MonitoredEmail>("/settings/monitored-email/verify", token, { email, otp });
}

export function listMonitoredEmails(token: string) {
  return authed<MonitoredEmail[]>("/settings/monitored-email", token);
}
