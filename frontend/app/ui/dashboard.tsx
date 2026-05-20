"use client";

import { Activity, Bell, Bot, DatabaseZap, FileSearch, Gauge, LogOut, Mail, Radio, Settings, ShieldAlert, Terminal } from "lucide-react";
import type React from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  API_BASE_URL,
  AlertItem,
  AuthOut,
  ChatMessage,
  EmailMessage,
  IncidentItem,
  KnowledgeHit,
  LogItem,
  NotificationItem,
  RuntimeConfig,
  RuleSuggestion,
  SocMetrics,
  TriageItem,
  User,
  authed,
  getAlertTriage,
  getChatHistory,
  getDeviceConsent,
  getIncidents,
  getMe,
  getMailboxEmailFeed,
  getRuntimeConfig,
  getSocMetrics,
  login,
  queryAssistant,
  register,
  requestImapEmailOtp,
  requestNotificationEmail,
  removeNotificationEmail,
  saveRuntimeConfig,
  searchKnowledge,
  streamUrl,
  submitFeedback,
  suggestRule,
  updateDeviceConsent,
  verifyImapEmail,
  verifyNotificationEmail,
  verifyOtp,
} from "@/lib/api";

type Page = "dashboard" | "logs" | "alerts" | "chat" | "settings";
type Connection = "offline" | "connecting" | "live";
type LiveEvent = { type: "log" | "alert_enriched"; log?: LogItem; alert?: AlertItem };

export function Dashboard() {
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [otpPurpose, setOtpPurpose] = useState<"register" | "login">("register");
  const [authMode, setAuthMode] = useState<"login" | "otp">("login");
  const [page, setPage] = useState<Page>("dashboard");
  const [error, setError] = useState("");
  const [connection, setConnection] = useState<Connection>("offline");
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [deviceConsent, setDeviceConsent] = useState(false);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [socMetrics, setSocMetrics] = useState<SocMetrics | null>(null);
  const [triageByAlert, setTriageByAlert] = useState<Record<string, TriageItem>>({});
  const [ruleSuggestions, setRuleSuggestions] = useState<RuleSuggestion[]>([]);
  const [knowledgeQuery, setKnowledgeQuery] = useState("brute force mitre");
  const [knowledgeHits, setKnowledgeHits] = useState<KnowledgeHit[]>([]);
  const [opsMessage, setOpsMessage] = useState("");
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const [mailboxFeed, setMailboxFeed] = useState<EmailMessage[]>([]);
  const [runtimeConfig, setRuntimeConfig] = useState<RuntimeConfig>({});
  const [notifEmail, setNotifEmail] = useState("");
  const [notifOtp, setNotifOtp] = useState("");
  const [imapOtp, setImapOtp] = useState("");
  const [settingsMessage, setSettingsMessage] = useState("");
  const [settingsLoading, setSettingsLoading] = useState(false);
  const feedRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const saved = localStorage.getItem("ai_soc_token");
    if (saved) setToken(saved);
  }, []);

  useEffect(() => {
    if (!token) return;
    void ensureAuthorized(() => getMe(token)).then((me) => {
      if (me) setCurrentUser(me);
    });
    void loadSnapshot(token);
    setConnection("connecting");
    const events = new EventSource(streamUrl(token));
    events.addEventListener("ready", () => setConnection("live"));
    events.addEventListener("log", (message) => {
      const payload = JSON.parse((message as MessageEvent).data) as LiveEvent;
      if (payload.log) {
        setLogs((items) => [ensureTime(payload.log!), ...items].slice(0, 200));
        if (payload.log.source_type === "email") {
          void ensureAuthorized(() => getMailboxEmailFeed(token, 100)).then((feed) => {
            if (feed) setMailboxFeed(feed);
          }).catch(() => {});
        }
      }
      if (payload.alert) setAlerts((items) => [payload.alert!, ...items.filter((item) => item.id !== payload.alert!.id)].slice(0, 120));
      requestAnimationFrame(() => {
        if (feedRef.current) feedRef.current.scrollTop = 0;
      });
    });
    events.addEventListener("alert_enriched", (message) => {
      const payload = JSON.parse((message as MessageEvent).data) as LiveEvent;
      if (payload.alert) setAlerts((items) => [payload.alert!, ...items.filter((item) => item.id !== payload.alert!.id)].slice(0, 120));
    });
    events.onerror = () => {
      setConnection("connecting");
      void ensureAuthorized(() => authed("/me", token));
    };
    return () => events.close();
  }, [token]);

  async function loadSnapshot(authToken: string) {
    try {
      const [nextLogs, nextAlerts, nextNotifications, nextIncidents, nextMailboxFeed] = await Promise.all([
        authed<LogItem[]>("/logs?limit=80", authToken),
        authed<AlertItem[]>("/alerts?limit=50", authToken),
        authed<NotificationItem[]>("/notifications?limit=50", authToken),
        getIncidents(authToken),
        getMailboxEmailFeed(authToken, 100),
      ]);
      setLogs(nextLogs);
      setAlerts(nextAlerts);
      setNotifications(nextNotifications);
      setIncidents(nextIncidents);
      setMailboxFeed(nextMailboxFeed);
      void refreshSocMetrics(authToken);
    } catch (error) {
      handleUnauthorized(error);
      return;
    }
    try {
      const user = await getMe(authToken);
      setCurrentUser(user);
      setNotifEmail(user.notification_email || "");
    } catch {}
    try {
      setDeviceConsent((await getDeviceConsent(authToken)).granted);
      setRuntimeConfig(await getRuntimeConfig(authToken));
    } catch {}
  }

  function saveAuth(result: AuthOut) {
    if (!result.token) {
      setError("Token không hợp lệ");
      return;
    }
    localStorage.setItem("ai_soc_token", result.token);
    setToken(result.token);
  }

  async function handleLogin() {
    setError("");
    try {
      await login(email, password);
      setOtp("");
      setOtpPurpose("login");
      setAuthMode("otp");
      setError("Đã gửi OTP đăng nhập tới email của bạn.");
    } catch (loginError) {
      setError(messageOf(loginError));
    }
  }

  async function handleRegister() {
    setError("");
    try {
      await register(email, password);
      setOtp("");
      setOtpPurpose("register");
      setAuthMode("otp");
      setError("Đã gửi OTP đăng ký tới email của bạn.");
    } catch (registerError) {
      setError(messageOf(registerError));
    }
  }

  async function handleVerifyOtp() {
    setError("");
    try {
      saveAuth(await verifyOtp(email, otp, otpPurpose));
      setAuthMode("login");
      setOtpPurpose("register");
    } catch (otpError) {
      setError(messageOf(otpError));
    }
  }

  function signOut() {
    localStorage.removeItem("ai_soc_token");
    setToken(null);
    setCurrentUser(null);
    setDeviceConsent(false);
    setLogs([]);
    setAlerts([]);
    setNotifications([]);
    setConnection("offline");
    setPage("dashboard");
  }

  async function grantDeviceConsent(granted: boolean) {
    if (!token) return;
    await ensureAuthorized(async () => {
      const result = await updateDeviceConsent(token, granted);
      setDeviceConsent(result.granted);
    });
  }

  async function sendChat() {
    if (!token || !chatInput.trim()) return;
    const question = chatInput.trim();
    setChatInput("");
    setChatLoading(true);
    try {
      const response = await queryAssistant(token, question);
      setChatHistory((items) => [...items, { id: crypto.randomUUID(), question, answer: response.answer, asked_at: new Date().toISOString() }]);
    } catch {
      setChatHistory((items) => [...items, { id: crypto.randomUUID(), question, answer: "AI hiện không phản hồi, vui lòng thử lại sau.", asked_at: new Date().toISOString() }]);
    }
    setChatLoading(false);
  }

  async function navigate(nextPage: Page) {
    setPage(nextPage);
    if (nextPage === "chat" && token && chatHistory.length === 0) {
      try {
        setChatHistory((await getChatHistory(token)).reverse());
      } catch {}
    }
    if (nextPage === "alerts" && token) {
      void refreshSocMetrics(token);
    }
  }

  async function refreshSocMetrics(authToken = token) {
    if (!authToken) return;
    try {
      setSocMetrics(await getSocMetrics(authToken));
    } catch {}
  }

  async function loadAlertTriage(alertId: string) {
    if (!token) return;
    setOpsMessage("");
    try {
      const triage = await ensureAuthorized(() => getAlertTriage(token, alertId));
      if (triage) setTriageByAlert((items) => ({ ...items, [alertId]: triage }));
    } catch (error) {
      setOpsMessage(messageOf(error));
    }
  }

  async function sendAlertFeedback(alertId: string, verdict: string) {
    if (!token) return;
    setOpsMessage("");
    try {
      await ensureAuthorized(() => submitFeedback(token, alertId, verdict, verdict === "false_positive" ? "Marked from dashboard" : ""));
      setOpsMessage("Đã ghi nhận feedback analyst.");
      void refreshSocMetrics(token);
    } catch (error) {
      setOpsMessage(messageOf(error));
    }
  }

  async function createRuleSuggestion(alertId: string) {
    if (!token) return;
    setOpsMessage("");
    try {
      const rule = await ensureAuthorized(() => suggestRule(token, alertId));
      if (rule) setRuleSuggestions((items) => [rule, ...items.filter((item) => item.id !== rule.id)].slice(0, 8));
      setOpsMessage("Đã sinh rule draft từ alert.");
      void refreshSocMetrics(token);
    } catch (error) {
      setOpsMessage(messageOf(error));
    }
  }

  async function runKnowledgeSearch() {
    if (!token || !knowledgeQuery.trim()) return;
    setOpsMessage("");
    try {
      const hits = await ensureAuthorized(() => searchKnowledge(token, knowledgeQuery.trim(), 6));
      if (hits) setKnowledgeHits(hits);
    } catch (error) {
      setOpsMessage(messageOf(error));
    }
  }

  async function saveSettingsConfig() {
    if (!token) return;
    setSettingsLoading(true);
    setSettingsMessage("");
    try {
      setRuntimeConfig(await saveRuntimeConfig(token, runtimeConfig));
      setSettingsMessage("Đã lưu cấu hình runtime. SMTP dùng ngay cho OTP/alert; IMAP sẽ được email-ingest đọc từ backend, restart email-ingest để backfill lại mail cũ.");
    } catch (error) {
      setSettingsMessage(messageOf(error));
    }
    setSettingsLoading(false);
  }

  async function requestNotifEmail() {
    if (!token) return;
    setSettingsLoading(true);
    try {
      const result = await ensureAuthorized(() => requestNotificationEmail(token, notifEmail));
      if (!result) return;
      setSettingsMessage(result.message || "Đã gửi email xác nhận.");
      if (result.dev_otp) setNotifOtp(result.dev_otp);
    } catch (error) {
      setSettingsMessage(messageOf(error));
    }
    setSettingsLoading(false);
  }

  async function verifyNotifEmail() {
    if (!token) return;
    setSettingsLoading(true);
    try {
      const result = await ensureAuthorized(() => verifyNotificationEmail(token, notifOtp));
      if (!result) return;
      setSettingsMessage(result.message || "Email thông báo đã xác nhận.");
      const me = await ensureAuthorized(() => getMe(token));
      if (me) setCurrentUser(me);
    } catch (error) {
      setSettingsMessage(messageOf(error));
    }
    setSettingsLoading(false);
  }

  async function requestImapOtp() {
    if (!token) return;
    const imapUser = (runtimeConfig.imap_user || "").trim();
    if (!imapUser) {
      setSettingsMessage("Cần nhập IMAP User trước khi gửi OTP.");
      return;
    }
    setSettingsLoading(true);
    try {
      const result = await ensureAuthorized(() => requestImapEmailOtp(token, imapUser));
      if (!result) return;
      setRuntimeConfig((config) => ({ ...config, imap_user: result.imap_user, imap_user_verified: null }));
      setSettingsMessage(result.message || "Đã gửi OTP xác nhận mailbox IMAP.");
    } catch (error) {
      setSettingsMessage(messageOf(error));
    }
    setSettingsLoading(false);
  }

  async function verifyImapOtp() {
    if (!token) return;
    const imapUser = (runtimeConfig.imap_user || "").trim();
    if (!imapUser) {
      setSettingsMessage("Cần nhập IMAP User trước khi xác nhận OTP.");
      return;
    }
    setSettingsLoading(true);
    try {
      const result = await ensureAuthorized(() => verifyImapEmail(token, imapUser, imapOtp));
      if (!result) return;
      setRuntimeConfig((config) => ({ ...config, imap_user: result.imap_user, imap_user_verified: result.imap_user }));
      setSettingsMessage(result.message || "Mailbox IMAP đã xác nhận. Restart email-ingest để backfill mail cũ.");
      const feed = await ensureAuthorized(() => getMailboxEmailFeed(token, 100));
      if (feed) setMailboxFeed(feed);
    } catch (error) {
      setSettingsMessage(messageOf(error));
    }
    setSettingsLoading(false);
  }

  const metrics = useMemo(() => ({
    logs: logs.length,
    emailLogs: logs.filter((item) => item.source_type === "email").length,
    alerts: alerts.length,
    critical: alerts.filter((item) => item.severity === "Critical").length,
  }), [alerts, logs]);

  function isUnauthorizedError(error: unknown): boolean {
    if (!(error instanceof Error)) return false;
    const message = error.message.toLowerCase();
    return message.includes("401") || message.includes("invalid token") || message.includes("inactive user") || message.includes("missing bearer token");
  }

  function handleUnauthorized(error: unknown) {
    if (!isUnauthorizedError(error)) return;
    localStorage.removeItem("ai_soc_token");
    setToken(null);
    setCurrentUser(null);
    setDeviceConsent(false);
    setLogs([]);
    setAlerts([]);
    setNotifications([]);
    setMailboxFeed([]);
    setConnection("offline");
    setError("Phiên đăng nhập đã hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại.");
  }

  async function ensureAuthorized<T>(fn: () => Promise<T>): Promise<T | null> {
    try {
      return await fn();
    } catch (error) {
      handleUnauthorized(error);
      throw error;
    }
  }

  if (!token) {
    return (
      <main className="login-wrap">
        <section className="login-panel">
          <div className="brand"><ShieldAlert size={22} /> AI-SOC Dashboard</div>
          <p className="muted">Đăng ký/đăng nhập dùng OTP qua SMTP email.</p>
          <label className="field">Email<input id="login-email" className="input" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
          <label className="field">Password<input id="login-password" className="input" type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
          {authMode === "otp" && <label className="field">OTP<input id="login-otp" className="input" value={otp} onChange={(event) => setOtp(event.target.value)} /></label>}
          <div className="error">{error}</div>
          <div className="button-row">
            {authMode === "otp" ? <button id="btn-verify-otp" className="button" type="button" onClick={handleVerifyOtp}>Verify OTP</button> : (
              <>
                <button id="btn-login" className="button" type="button" onClick={handleLogin}>Login</button>
                <button id="btn-register" className="button secondary" type="button" onClick={handleRegister}>Register</button>
              </>
            )}
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><ShieldAlert size={22} /> AI-SOC</div>
        <NavButton id="nav-dashboard" active={page === "dashboard"} onClick={() => navigate("dashboard")} icon={<Activity size={18} />} label="Dashboard" />
        <NavButton id="nav-logs" active={page === "logs"} onClick={() => navigate("logs")} icon={<DatabaseZap size={18} />} label="Logs & Email" />
        <NavButton id="nav-alerts" active={page === "alerts"} onClick={() => navigate("alerts")} icon={<Bell size={18} />} label="Alerts" />
        <NavButton id="nav-chat" active={page === "chat"} onClick={() => navigate("chat")} icon={<Bot size={18} />} label="Trợ lý AI" />
        <NavButton id="nav-settings" active={page === "settings"} onClick={() => navigate("settings")} icon={<Settings size={18} />} label="Cài đặt" />
      </aside>
      <section className="content">
        <div className="topbar">
          <div>
            <h1 className="title">{titleOf(page)}</h1>
            <div className="muted">API: {API_BASE_URL}</div>
          </div>
          <div className="button-row">
            <span className={`badge ${connection === "live" ? "green" : ""}`}><Radio size={14} /> {connection}</span>
            <button id="btn-signout" className="button secondary icon-button" type="button" onClick={signOut} title="Sign out"><LogOut size={16} /></button>
          </div>
        </div>

        {!deviceConsent && page !== "settings" && <ConsentGate onGrant={() => grantDeviceConsent(true)} />}
        {deviceConsent && page === "dashboard" && <DashboardView metrics={metrics} logs={logs} alerts={alerts} notifications={notifications} mailboxFeed={mailboxFeed} feedRef={feedRef} />}
        {deviceConsent && page === "logs" && <LogsView logs={logs} />}
        {page === "alerts" && (
          <AlertsView
            alerts={alerts}
            incidents={incidents}
            socMetrics={socMetrics}
            triageByAlert={triageByAlert}
            ruleSuggestions={ruleSuggestions}
            knowledgeQuery={knowledgeQuery}
            setKnowledgeQuery={setKnowledgeQuery}
            knowledgeHits={knowledgeHits}
            opsMessage={opsMessage}
            onLoadTriage={loadAlertTriage}
            onFeedback={sendAlertFeedback}
            onSuggestRule={createRuleSuggestion}
            onKnowledgeSearch={runKnowledgeSearch}
          />
        )}
        {page === "chat" && <ChatView history={chatHistory} input={chatInput} setInput={setChatInput} loading={chatLoading} onSend={sendChat} />}
        {page === "settings" && (
          <SettingsView
            currentUser={currentUser}
            deviceConsent={deviceConsent}
            onDeviceConsent={grantDeviceConsent}
            runtimeConfig={runtimeConfig}
            setRuntimeConfig={setRuntimeConfig}
            onSaveRuntimeConfig={saveSettingsConfig}
            notifEmail={notifEmail}
            setNotifEmail={setNotifEmail}
            notifOtp={notifOtp}
            setNotifOtp={setNotifOtp}
            onRequestNotif={requestNotifEmail}
            onVerifyNotif={verifyNotifEmail}
            onRemoveNotif={async () => {
              if (!token) return;
              await removeNotificationEmail(token);
              setCurrentUser(await getMe(token));
              setNotifEmail("");
            }}
            imapOtp={imapOtp}
            setImapOtp={setImapOtp}
            onRequestImapOtp={requestImapOtp}
            onVerifyImapOtp={verifyImapOtp}
            message={settingsMessage}
            loading={settingsLoading}
          />
        )}
      </section>
    </main>
  );
}

function NavButton({ id, active, onClick, icon, label }: { id: string; active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return <button id={id} className={`nav-item${active ? " active" : ""}`} type="button" onClick={onClick}>{icon}{label}</button>;
}

function ConsentGate({ onGrant }: { onGrant: () => void }) {
  return (
    <Panel title="Yêu cầu cấp quyền truy cập log thiết bị" badge="required">
      <div style={{ padding: 20, maxWidth: 720 }}>
        <p className="summary">Trước khi hiển thị log/email realtime, hệ thống cần bạn xác nhận cho phép thu thập và hiển thị log đã tóm tắt từ thiết bị đang sử dụng hoặc collector đã cấu hình.</p>
        <button id="btn-grant-device-consent" className="button" type="button" onClick={onGrant}>Tôi đồng ý cấp quyền</button>
      </div>
    </Panel>
  );
}

function DashboardView({ metrics, logs, alerts, notifications, mailboxFeed, feedRef }: { metrics: { logs: number; emailLogs: number; alerts: number; critical: number }; logs: LogItem[]; alerts: AlertItem[]; notifications: NotificationItem[]; mailboxFeed: EmailMessage[]; feedRef: React.RefObject<HTMLDivElement | null> }) {
  return (
    <>
      <section className="grid summary-grid">
        <Metric label="Realtime logs" value={metrics.logs} icon={<Terminal size={18} />} />
        <Metric label="Email events" value={metrics.emailLogs} icon={<Mail size={18} />} />
        <Metric label="Open alerts" value={metrics.alerts} icon={<ShieldAlert size={18} />} />
        <Metric label="Critical" value={metrics.critical} icon={<Bell size={18} />} />
      </section>
      <section className="grid main-grid">
        <Panel title="Live log/email stream" badge="auto-updating">
          <div className="feed" ref={feedRef}>
            {logs.length === 0 ? <Empty text="Chưa có log. Gửi webhook hoặc bật collector/email ingest để thấy dòng log chạy tại đây." /> : logs.map((item) => <FeedRow key={`${item.id}-${item.received_at}`} item={item} />)}
          </div>
        </Panel>
        <div className="grid">
          <Panel title="Mailbox IMAP đã nhận" badge={`${mailboxFeed.length} mails`}>
            {mailboxFeed.length === 0 ? <Empty text="Chưa có mail nào từ mailbox IMAP đã xác thực." /> : mailboxFeed.slice(0, 12).map((mail) => (
              <div className="alert-row" key={mail.id}>
                <div className="timestamp">{formatTime(mail.received_at)}</div>
                <div>
                  <div className="source">{mail.subject || "(No subject)"}</div>
                  <div className="summary">{mail.sender} {" -> "} {(mail.recipients || []).join(", ")}</div>
                </div>
                <span className="badge email">{mail.mailbox}</span>
              </div>
            ))}
          </Panel>
          <Panel title="Alerts" badge={`${alerts.length} total`}>{alerts.length === 0 ? <Empty text="Chưa có alert." /> : alerts.slice(0, 12).map((item) => <AlertRow key={item.id} item={item} />)}</Panel>
          <Panel title="Email notifications" badge={`${notifications.length} queued`}>
            {notifications.length === 0 ? <Empty text="Chưa có notification." /> : notifications.slice(0, 8).map((item) => (
              <div className="alert-row" key={item.id}><div className="timestamp">{formatTime(item.created_at)}</div><div><div className="source">{item.recipient}</div><div className="summary">{item.channel} notification {item.status}</div></div><span className="badge">{item.status}</span></div>
            ))}
          </Panel>
        </div>
      </section>
    </>
  );
}

function LogsView({ logs }: { logs: LogItem[] }) {
  const [filter, setFilter] = useState("all");
  const filtered = filter === "all" ? logs : logs.filter((item) => item.source_type === filter);
  return (
    <>
      <div className="button-row" style={{ marginBottom: 14 }}>{["all", "email", "webhook", "ubuntu_agent", "windows_agent"].map((item) => <button key={item} className={`button ${filter === item ? "" : "secondary"}`} type="button" onClick={() => setFilter(item)}>{item}</button>)}</div>
      <Panel title="Logs" badge={`${filtered.length} items`}><div className="feed">{filtered.length === 0 ? <Empty text="Không có log nào." /> : filtered.map((item) => <FeedRow key={`${item.id}-${item.received_at}`} item={item} />)}</div></Panel>
    </>
  );
}

function AlertsView({
  alerts,
  incidents,
  socMetrics,
  triageByAlert,
  ruleSuggestions,
  knowledgeQuery,
  setKnowledgeQuery,
  knowledgeHits,
  opsMessage,
  onLoadTriage,
  onFeedback,
  onSuggestRule,
  onKnowledgeSearch,
}: {
  alerts: AlertItem[];
  incidents: IncidentItem[];
  socMetrics: SocMetrics | null;
  triageByAlert: Record<string, TriageItem>;
  ruleSuggestions: RuleSuggestion[];
  knowledgeQuery: string;
  setKnowledgeQuery: (value: string) => void;
  knowledgeHits: KnowledgeHit[];
  opsMessage: string;
  onLoadTriage: (alertId: string) => void;
  onFeedback: (alertId: string, verdict: string) => void;
  onSuggestRule: (alertId: string) => void;
  onKnowledgeSearch: () => void;
}) {
  return (
    <>
      <section className="grid summary-grid">
        <Metric label="Open alerts" value={socMetrics?.open_alerts ?? alerts.length} icon={<ShieldAlert size={18} />} />
        <Metric label="High/Critical" value={(socMetrics?.high_alerts ?? 0) + (socMetrics?.critical_alerts ?? 0)} icon={<Gauge size={18} />} />
        <Metric label="Feedback" value={socMetrics?.feedback_count ?? 0} icon={<Activity size={18} />} />
        <Metric label="Generated rules" value={socMetrics?.generated_rules ?? ruleSuggestions.length} icon={<FileSearch size={18} />} />
      </section>
      {opsMessage && <div className="settings-message" style={{ marginBottom: 14 }}>{opsMessage}</div>}
      <div className="grid main-grid">
        <Panel title="Alerts triage & feedback" badge={`${alerts.length} total`}>
          <div className="feed">
            {alerts.length === 0 ? <Empty text="Không có cảnh báo mới." /> : alerts.map((item) => (
              <AlertOpsRow
                key={item.id}
                item={item}
                triage={triageByAlert[item.id]}
                onLoadTriage={onLoadTriage}
                onFeedback={onFeedback}
                onSuggestRule={onSuggestRule}
              />
            ))}
          </div>
        </Panel>
        <div className="grid">
          <Panel title="Incidents" badge={`${incidents.length} total`}>
            <div className="compact-feed">{incidents.length === 0 ? <Empty text="Không có incident." /> : incidents.map((item) => <div className="alert-row" key={item.id}><div className="timestamp">{formatTime(item.created_at)}</div><div><div className="source">{item.name}</div><div className="summary">{item.description}</div></div><span className={`badge sev-${item.severity}`}>{item.severity}</span></div>)}</div>
          </Panel>
          <Panel title="Knowledge search" badge={`${knowledgeHits.length} hits`}>
            <div className="settings-body">
              <div className="inline-search">
                <input className="input" value={knowledgeQuery} onChange={(event) => setKnowledgeQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") onKnowledgeSearch(); }} placeholder="MITRE, CVE, phishing..." />
                <button className="button" type="button" onClick={onKnowledgeSearch}>Tìm</button>
              </div>
              <div className="mini-list">
                {knowledgeHits.length === 0 ? <Empty text="Tìm trong knowledge base MITRE/CVE/playbook." /> : knowledgeHits.map((item) => (
                  <div className="knowledge-item" key={`${item.source}-${item.title}`}>
                    <div className="source">{item.title}</div>
                    <div className="muted">{item.source} - score {item.score.toFixed(2)}</div>
                    <div className="summary">{item.text}</div>
                  </div>
                ))}
              </div>
            </div>
          </Panel>
          <Panel title="Rule suggestions" badge={`${ruleSuggestions.length} drafts`}>
            <div className="compact-feed">
              {ruleSuggestions.length === 0 ? <Empty text="Chọn một alert rồi bấm Generate rule." /> : ruleSuggestions.map((item) => (
                <div className="knowledge-item" key={item.id}>
                  <div className="source">{item.name}</div>
                  <div className="summary">{item.rule_type} - {item.status} - backtest {String(item.backtest_summary?.matches ?? 0)} matches</div>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

function AlertOpsRow({ item, triage, onLoadTriage, onFeedback, onSuggestRule }: { item: AlertItem; triage?: TriageItem; onLoadTriage: (alertId: string) => void; onFeedback: (alertId: string, verdict: string) => void; onSuggestRule: (alertId: string) => void }) {
  return (
    <div className="alert-ops-row">
      <div className="alert-row dense">
        <div className="timestamp">{formatTime(item.detected_at)}</div>
        <div>
          <div className="source">{item.message}</div>
          <div className="summary">{item.ai_summary}</div>
          <div className="muted mono">{item.id}</div>
        </div>
        <span className={`badge sev-${item.severity}`}>{item.severity}</span>
      </div>
      {triage && (
        <div className="triage-box">
          <span className="badge green">{triage.priority}</span>
          <span>Risk {triage.risk_score.toFixed(2)}</span>
          <span>Confidence {triage.confidence.toFixed(2)}</span>
          <span>{triage.mitre_techniques.join(", ") || "No MITRE"}</span>
          <div className="summary">{triage.recommendations.join(" ")}</div>
        </div>
      )}
      <div className="button-row row-actions">
        <button className="button secondary" type="button" onClick={() => onLoadTriage(item.id)}>Triage</button>
        <button className="button secondary" type="button" onClick={() => onFeedback(item.id, "true_positive")}>True positive</button>
        <button className="button secondary" type="button" onClick={() => onFeedback(item.id, "false_positive")}>False positive</button>
        <button className="button" type="button" onClick={() => onSuggestRule(item.id)}>Generate rule</button>
      </div>
    </div>
  );
}

function ChatView({ history, input, setInput, loading, onSend }: { history: ChatMessage[]; input: string; setInput: (value: string) => void; loading: boolean; onSend: () => void }) {
  return (
    <Panel title="Chat với Trợ lý AI" badge="RAG + LLM">
      <div className="chat-container">
        <div className="chat-messages">
          {history.length === 0 && !loading && <div className="chat-empty"><Bot size={48} style={{ opacity: 0.3 }} /><p className="muted">Hỏi Trợ lý AI về mối đe dọa, IP đáng ngờ hoặc cảnh báo.</p></div>}
          {history.map((item) => <div key={item.id} className="chat-pair"><div className="chat-bubble user"><strong>Bạn:</strong> {item.question}</div><div className="chat-bubble ai"><strong>AI:</strong> {item.answer}</div></div>)}
          {loading && <div className="chat-bubble ai">Đang phân tích...</div>}
        </div>
        <div className="chat-input-row">
          <input id="chat-input" className="input" value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") onSend(); }} placeholder="Nhập câu hỏi an ninh mạng..." />
          <button id="btn-send-chat" className="button" type="button" disabled={loading || !input.trim()} onClick={onSend}>Gửi</button>
        </div>
      </div>
    </Panel>
  );
}

function SettingsView(props: {
  currentUser: User | null;
  deviceConsent: boolean;
  onDeviceConsent: (granted: boolean) => void;
  runtimeConfig: RuntimeConfig;
  setRuntimeConfig: (config: RuntimeConfig) => void;
  onSaveRuntimeConfig: () => void;
  notifEmail: string;
  setNotifEmail: (email: string) => void;
  notifOtp: string;
  setNotifOtp: (otp: string) => void;
  onRequestNotif: () => void;
  onVerifyNotif: () => void;
  onRemoveNotif: () => void;
  imapOtp: string;
  setImapOtp: (otp: string) => void;
  onRequestImapOtp: () => void;
  onVerifyImapOtp: () => void;
  message: string;
  loading: boolean;
}) {
  const c = props.runtimeConfig;
  const update = (patch: RuntimeConfig) => props.setRuntimeConfig({ ...c, ...patch });
  return (
    <div className="settings-grid">
      <Panel title="SMTP Auth & quyền log" badge="smtp otp">
        <div className="settings-body">
          <div className="muted">Email đăng nhập: {props.currentUser?.email || "-"}</div>
          <div className="muted">Xác thực đăng ký/đăng nhập dùng OTP gửi qua SMTP.</div>
          <div className="button-row" style={{ marginTop: 12 }}>
            <button className="button" type="button" disabled={props.deviceConsent} onClick={() => props.onDeviceConsent(true)}>Cấp quyền log thiết bị</button>
            <button className="button secondary" type="button" disabled={!props.deviceConsent} onClick={() => props.onDeviceConsent(false)}>Thu hồi quyền</button>
          </div>
        </div>
      </Panel>

      <Panel title="Cloud LLM API" badge="encrypted">
        <div className="settings-body">
          <div className="muted" style={{ marginBottom: 12 }}>Dùng LLM cloud qua OpenAI-compatible API. Cấu hình này được backend và enrichment worker đọc trực tiếp khi phân tích.</div>
          <label className="field">LLM Base URL<input className="input" value={c.llm_base_url || ""} onChange={(e) => update({ llm_base_url: e.target.value })} placeholder="https://api.openai.com/v1 hoặc https://api.deepseek.com/v1" /></label>
          <label className="field">LLM Model<input className="input" value={c.llm_model || ""} onChange={(e) => update({ llm_model: e.target.value })} placeholder="gpt-4o-mini hoặc deepseek-chat" /></label>
          <label className="field">LLM API Key<input className="input" value={c.llm_api_key || ""} onChange={(e) => update({ llm_api_key: e.target.value })} placeholder="sk-..." /></label>
          <button id="btn-save-runtime-config" className="button" type="button" disabled={props.loading} onClick={props.onSaveRuntimeConfig}>Lưu cấu hình</button>
        </div>
      </Panel>

      <Panel title="SMTP gửi OTP/alert" badge="runtime">
        <div className="settings-body">
          <div className="muted" style={{ marginBottom: 12 }}>Tài khoản gửi OTP đăng ký/đăng nhập, OTP xác nhận mailbox IMAP và email alert.</div>
          <label className="field">SMTP Host<input className="input" value={c.smtp_host || ""} onChange={(e) => update({ smtp_host: e.target.value })} placeholder="smtp.gmail.com" /></label>
          <label className="field">SMTP Port<input className="input" value={c.smtp_port || ""} onChange={(e) => update({ smtp_port: e.target.value })} placeholder="465" /></label>
          <label className="field">SMTP Username<input className="input" value={c.smtp_username || ""} onChange={(e) => update({ smtp_username: e.target.value })} placeholder="sender@gmail.com" /></label>
          <label className="field">SMTP App Password<input className="input" type="password" value={c.smtp_password || ""} onChange={(e) => update({ smtp_password: e.target.value })} placeholder="Gmail app password" /></label>
          <label className="field">SMTP From<input className="input" value={c.smtp_from || ""} onChange={(e) => update({ smtp_from: e.target.value })} placeholder="sender@gmail.com" /></label>
          <button className="button" type="button" disabled={props.loading} onClick={props.onSaveRuntimeConfig}>Lưu SMTP</button>
        </div>
      </Panel>

      <Panel title="IMAP đọc mailbox" badge="runtime">
        <div className="settings-body">
          <div className="muted" style={{ marginBottom: 12 }}>IMAP User là mailbox hệ thống đọc. Cần xác nhận OTP cho chính email này trước khi email-ingest được phép polling.</div>
          <label className="field">IMAP Host<input className="input" value={c.imap_host || ""} onChange={(e) => update({ imap_host: e.target.value })} placeholder="imap.gmail.com" /></label>
          <label className="field">IMAP Port<input className="input" value={c.imap_port || ""} onChange={(e) => update({ imap_port: e.target.value })} placeholder="993" /></label>
          <label className="field">IMAP User<input className="input" value={c.imap_user || ""} onChange={(e) => update({ imap_user: e.target.value })} placeholder="mailbox@gmail.com" /></label>
          <label className="field">IMAP App Password<input className="input" type="password" value={c.imap_password || ""} onChange={(e) => update({ imap_password: e.target.value })} placeholder="Gmail app password" /></label>
          <label className="field">IMAP Folder<input className="input" value={c.imap_folder || ""} onChange={(e) => update({ imap_folder: e.target.value })} placeholder="INBOX" /></label>
          <label className="field">Backfill Limit<input className="input" value={c.imap_backfill_limit || ""} onChange={(e) => update({ imap_backfill_limit: e.target.value })} placeholder="50" /></label>
          <div className="muted">Trạng thái OTP: {c.imap_user && c.imap_user_verified === c.imap_user ? "đã xác nhận" : "chưa xác nhận"}</div>
          <div className="button-row">
            <button className="button" type="button" disabled={props.loading} onClick={props.onSaveRuntimeConfig}>Lưu IMAP</button>
            <button className="button secondary" type="button" disabled={props.loading || !c.imap_user?.trim()} onClick={props.onRequestImapOtp}>Gửi OTP IMAP</button>
          </div>
          <label className="field">OTP IMAP<input className="input" value={props.imapOtp} onChange={(e) => props.setImapOtp(e.target.value)} /></label>
          <button className="button" type="button" disabled={props.loading || !props.imapOtp.trim() || !c.imap_user?.trim()} onClick={props.onVerifyImapOtp}>Xác nhận IMAP</button>
        </div>
      </Panel>

      <Panel title="Email nhận alert" badge="verified">
        <div className="settings-body">
          <label className="field">Email nhận thông báo<input className="input" value={props.notifEmail} onChange={(e) => props.setNotifEmail(e.target.value)} /></label>
          <div className="button-row">
            <button className="button" type="button" disabled={props.loading || !props.notifEmail.trim()} onClick={props.onRequestNotif}>Gửi mã xác nhận</button>
            <button className="button secondary" type="button" onClick={props.onRemoveNotif}>Xóa</button>
          </div>
          <label className="field">OTP<input className="input" value={props.notifOtp} onChange={(e) => props.setNotifOtp(e.target.value)} /></label>
          <button className="button" type="button" disabled={props.loading || !props.notifOtp.trim()} onClick={props.onVerifyNotif}>Xác nhận OTP</button>
        </div>
      </Panel>

      {props.message && <div className="settings-message">{props.message}</div>}
    </div>
  );
}

function Metric({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return <div className="metric"><div className="metric-label">{icon} {label}</div><div className="metric-value">{value}</div></div>;
}

function Panel({ title, badge, children }: { title: string; badge: string; children: React.ReactNode }) {
  return <section className="panel"><header className="panel-header"><h2 className="panel-title">{title}</h2><span className="badge">{badge}</span></header>{children}</section>;
}

function FeedRow({ item }: { item: LogItem }) {
  return <div className="feed-row"><div className="timestamp">{formatTime(item.received_at)}</div><div><div className="source">{item.source}</div><div className="summary">{item.log_summary}</div><div className="muted mono">{item.correlation_id}</div></div><span className={`badge ${item.source_type === "email" ? "email" : ""}`}>{item.source_type}</span></div>;
}

function AlertRow({ item }: { item: AlertItem }) {
  return <div className="alert-row"><div className="timestamp">{formatTime(item.detected_at)}</div><div><div className="source">{item.message}</div><div className="summary">{item.ai_summary}</div></div><span className={`badge sev-${item.severity}`}>{item.severity}</span></div>;
}

function Empty({ text }: { text: string }) {
  return <div style={{ padding: 16 }} className="muted">{text}</div>;
}

function ensureTime(item: LogItem): LogItem {
  return { ...item, received_at: item.received_at || new Date().toISOString() };
}

function formatTime(value: string) {
  return value ? new Date(value).toLocaleTimeString() : new Date().toLocaleTimeString();
}

function titleOf(page: Page) {
  return page === "dashboard" ? "Realtime SOC Monitor" : page === "logs" ? "Logs & Email" : page === "alerts" ? "Alerts & Incidents" : page === "chat" ? "Trợ lý AI" : "Cài đặt";
}

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : "Có lỗi xảy ra";
}
