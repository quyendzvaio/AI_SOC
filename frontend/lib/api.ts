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
  smtp_host?: string | null;
  smtp_port?: string | null;
  smtp_username?: string | null;
  smtp_password?: string | null;
  smtp_from?: string | null;
  imap_host?: string | null;
  imap_port?: string | null;
  imap_user?: string | null;
  imap_password?: string | null;
  imap_folder?: string | null;
  imap_backfill_limit?: string | null;
  imap_user_verified?: string | null;
};

export type DeviceConsent = {
  granted: boolean;
  granted_at: string | null;
};

export type ImapEmailResponse = {
  imap_user: string | null;
  is_verified: boolean;
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

export type TriageItem = {
  alert_id: string;
  risk_score: number;
  confidence: number;
  priority: string;
  mitre_techniques: string[];
  threat_labels: string[];
  recommendations: string[];
};

export type SocMetrics = {
  total_logs: number;
  total_alerts: number;
  open_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  total_incidents: number;
  feedback_count: number;
  true_positive_feedback: number;
  false_positive_feedback: number;
  generated_rules: number;
  top_mitre: Array<{ technique: string; count: number }>;
};

export type KnowledgeHit = {
  title: string;
  source: string;
  text: string;
  score: number;
};

export type RuleSuggestion = {
  id: string;
  source_alert_id: string | null;
  name: string;
  rule_type: string;
  rule_body: Record<string, unknown>;
  backtest_summary: Record<string, unknown>;
  status: string;
  created_at: string;
};

export type AnalystFeedback = {
  id: string;
  alert_id: string;
  verdict: string;
  corrected_severity: AlertItem["severity"] | null;
  corrected_mitre: string[];
  notes: string;
  created_at: string;
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

function resolveApiBaseUrl() {
  const configured = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
  if (typeof window === "undefined") return configured;
  try {
    const url = new URL(configured);
    const uiHost = window.location.hostname;
    if ((url.hostname === "localhost" || url.hostname === "127.0.0.1") && uiHost && uiHost !== url.hostname) {
      url.hostname = uiHost;
      return url.origin;
    }
    return url.origin;
  } catch {
    return configured;
  }
}

export const API_BASE_URL = resolveApiBaseUrl();

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

export function getMailboxEmailFeed(token: string, limit = 100) {
  return authed<EmailMessage[]>(`/emails/mailbox?limit=${limit}`, token);
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

export function requestImapEmailOtp(token: string, imapUser: string) {
  return authedPost<ImapEmailResponse>("/settings/imap-email/otp", token, { imap_user: imapUser });
}

export function verifyImapEmail(token: string, imapUser: string, otp: string) {
  return authedPost<ImapEmailResponse>("/settings/imap-email/verify", token, { imap_user: imapUser, otp });
}

export function getSocMetrics(token: string) {
  return authed<SocMetrics>("/metrics/soc", token);
}

export function getAlertTriage(token: string, alertId: string) {
  return authed<TriageItem>(`/alerts/${alertId}/triage`, token);
}

export function searchKnowledge(token: string, query: string, limit = 6) {
  return authed<KnowledgeHit[]>(`/knowledge/search?q=${encodeURIComponent(query)}&limit=${limit}`, token);
}

export function submitFeedback(token: string, alertId: string, verdict: string, notes = "") {
  return authedPost<AnalystFeedback>("/feedback", token, { alert_id: alertId, verdict, notes });
}

export function suggestRule(token: string, alertId: string) {
  return authedPost<RuleSuggestion>(`/rules/suggest/${alertId}`, token, {});
}
