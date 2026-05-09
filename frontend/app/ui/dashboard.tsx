"use client";

import { Activity, Bell, DatabaseZap, LogOut, Mail, Radio, ShieldAlert, Terminal } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  API_BASE_URL,
  AlertItem,
  AuthOut,
  LogItem,
  NotificationItem,
  authed,
  login,
  register,
  streamUrl,
  verifyOtp,
} from "@/lib/api";

type Connection = "offline" | "connecting" | "live";

type LiveEvent = {
  type: "log" | "alert_enriched";
  log?: LogItem;
  alert?: AlertItem;
};

const DEMO_PASSWORD = "StrongPass123!";

export function Dashboard() {
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState("soc@example.com");
  const [password, setPassword] = useState(DEMO_PASSWORD);
  const [otp, setOtp] = useState("");
  const [mode, setMode] = useState<"login" | "otp">("login");
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [connection, setConnection] = useState<Connection>("offline");
  const [error, setError] = useState("");
  const feedRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const saved = localStorage.getItem("ai_soc_token");
    if (saved) setToken(saved);
  }, []);

  useEffect(() => {
    if (!token) return;
    void loadSnapshot(token);
    setConnection("connecting");
    const events = new EventSource(streamUrl(token));
    events.addEventListener("ready", () => setConnection("live"));
    events.addEventListener("log", (message) => {
      const payload = JSON.parse((message as MessageEvent).data) as LiveEvent;
      if (payload.log) {
        setLogs((current) => [withReceivedAt(payload.log!), ...current].slice(0, 200));
      }
      if (payload.alert) {
        setAlerts((current) => [payload.alert!, ...current.filter((item) => item.id !== payload.alert!.id)].slice(0, 100));
      }
      requestAnimationFrame(() => {
        if (feedRef.current) feedRef.current.scrollTop = 0;
      });
    });
    events.addEventListener("alert_enriched", (message) => {
      const payload = JSON.parse((message as MessageEvent).data) as LiveEvent;
      if (payload.alert) {
        setAlerts((current) => [payload.alert!, ...current.filter((item) => item.id !== payload.alert!.id)].slice(0, 100));
      }
    });
    events.onerror = () => setConnection("connecting");
    return () => events.close();
  }, [token]);

  async function loadSnapshot(authToken: string) {
    const [nextLogs, nextAlerts, nextNotifications] = await Promise.all([
      authed<LogItem[]>("/logs?limit=80", authToken),
      authed<AlertItem[]>("/alerts?limit=50", authToken),
      authed<NotificationItem[]>("/notifications?limit=50", authToken),
    ]);
    setLogs(nextLogs);
    setAlerts(nextAlerts);
    setNotifications(nextNotifications);
  }

  async function handleLogin() {
    setError("");
    try {
      const result = await login(email, password);
      saveAuth(result);
    } catch (loginError) {
      setError(messageOf(loginError));
    }
  }

  async function handleRegister() {
    setError("");
    try {
      const result = await register(email, password);
      const devOtp = result.token?.replace("DEV_OTP:", "");
      if (devOtp) setOtp(devOtp);
      setMode("otp");
    } catch (registerError) {
      setError(messageOf(registerError));
    }
  }

  async function handleVerifyOtp() {
    setError("");
    try {
      const result = await verifyOtp(email, otp);
      saveAuth(result);
      setMode("login");
    } catch (otpError) {
      setError(messageOf(otpError));
    }
  }

  function saveAuth(result: AuthOut) {
    if (!result.token) {
      setError("Token không hợp lệ");
      return;
    }
    localStorage.setItem("ai_soc_token", result.token);
    setToken(result.token);
  }

  function signOut() {
    localStorage.removeItem("ai_soc_token");
    setToken(null);
    setLogs([]);
    setAlerts([]);
    setNotifications([]);
    setConnection("offline");
  }

  const metrics = useMemo(() => {
    const emailLogs = logs.filter((item) => item.source_type === "email").length;
    const critical = alerts.filter((item) => item.severity === "Critical").length;
    return {
      logs: logs.length,
      emailLogs,
      alerts: alerts.length,
      critical,
    };
  }, [alerts, logs]);

  if (!token) {
    return (
      <main className="login-wrap">
        <section className="login-panel">
          <div className="brand">
            <ShieldAlert size={22} />
            AI-SOC Dashboard
          </div>
          <p className="muted">Đăng nhập hoặc đăng ký nhanh để xem log/email realtime.</p>
          <label className="field">
            Email
            <input className="input" value={email} onChange={(event) => setEmail(event.target.value)} />
          </label>
          <label className="field">
            Password
            <input className="input" type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </label>
          {mode === "otp" && (
            <label className="field">
              OTP
              <input className="input" value={otp} onChange={(event) => setOtp(event.target.value)} />
            </label>
          )}
          <div className="error">{error}</div>
          <div className="button-row">
            {mode === "otp" ? (
              <button className="button" onClick={handleVerifyOtp}>
                Verify OTP
              </button>
            ) : (
              <>
                <button className="button" onClick={handleLogin}>
                  Login
                </button>
                <button className="button secondary" onClick={handleRegister}>
                  Register
                </button>
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
        <div className="brand">
          <ShieldAlert size={22} />
          AI-SOC
        </div>
        <div className="nav-item active">
          <Activity size={18} />
          Realtime Dashboard
        </div>
        <div className="nav-item">
          <DatabaseZap size={18} />
          Logs & Email
        </div>
        <div className="nav-item">
          <Bell size={18} />
          Alerts
        </div>
      </aside>

      <section className="content">
        <div className="topbar">
          <div>
            <h1 className="title">Realtime SOC Monitor</h1>
            <div className="muted">API: {API_BASE_URL}</div>
          </div>
          <div className="button-row">
            <span className={`badge ${connection === "live" ? "green" : ""}`}>
              <Radio size={14} />
              {connection}
            </span>
            <button className="button secondary" onClick={signOut} title="Sign out">
              <LogOut size={16} />
            </button>
          </div>
        </div>

        <section className="grid summary-grid">
          <Metric label="Realtime logs" value={metrics.logs} icon={<Terminal size={18} />} />
          <Metric label="Email events" value={metrics.emailLogs} icon={<Mail size={18} />} />
          <Metric label="Open alerts" value={metrics.alerts} icon={<ShieldAlert size={18} />} />
          <Metric label="Critical" value={metrics.critical} icon={<Bell size={18} />} />
        </section>

        <section className="grid main-grid">
          <Panel title="Live log/email stream" badge="auto-updating">
            <div className="feed" ref={feedRef}>
              {logs.length === 0 ? (
                <Empty text="Chưa có log. Gửi webhook hoặc bật collector/email ingest để thấy dòng log chạy tại đây." />
              ) : (
                logs.map((item) => <FeedRow key={`${item.id}-${item.received_at}`} item={item} />)
              )}
            </div>
          </Panel>

          <div className="grid">
            <Panel title="Alerts" badge={`${alerts.length} total`}>
              {alerts.length === 0 ? (
                <Empty text="Chưa có alert." />
              ) : (
                alerts.slice(0, 12).map((item) => <AlertRow key={item.id} item={item} />)
              )}
            </Panel>
            <Panel title="Email notifications" badge={`${notifications.length} queued`}>
              {notifications.length === 0 ? (
                <Empty text="Chưa có notification." />
              ) : (
                notifications.slice(0, 8).map((item) => (
                  <div className="alert-row" key={item.id}>
                    <div className="timestamp">{formatTime(item.created_at)}</div>
                    <div>
                      <div className="source">{item.recipient}</div>
                      <div className="summary">{item.channel} notification {item.status}</div>
                    </div>
                    <span className="badge">{item.status}</span>
                  </div>
                ))
              )}
            </Panel>
          </div>
        </section>
      </section>
    </main>
  );
}

function Metric({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <div className="metric">
      <div className="metric-label">
        {icon} {label}
      </div>
      <div className="metric-value">{value}</div>
    </div>
  );
}

function Panel({ title, badge, children }: { title: string; badge: string; children: React.ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-header">
        <h2 className="panel-title">{title}</h2>
        <span className="badge">{badge}</span>
      </header>
      {children}
    </section>
  );
}

function FeedRow({ item }: { item: LogItem }) {
  const isEmail = item.source_type === "email";
  return (
    <div className="feed-row">
      <div className="timestamp">{formatTime(item.received_at)}</div>
      <div>
        <div className="source">{item.source}</div>
        <div className="summary">{item.log_summary}</div>
        <div className="muted mono">{item.correlation_id}</div>
      </div>
      <span className={`badge ${isEmail ? "email" : ""}`}>{item.source_type}</span>
    </div>
  );
}

function AlertRow({ item }: { item: AlertItem }) {
  return (
    <div className="alert-row">
      <div className="timestamp">{formatTime(item.detected_at)}</div>
      <div>
        <div className="source">{item.message}</div>
        <div className="summary">{item.ai_summary}</div>
      </div>
      <span className={`badge sev-${item.severity}`}>{item.severity}</span>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div style={{ padding: 16 }} className="muted">{text}</div>;
}

function withReceivedAt(item: LogItem): LogItem {
  return { ...item, received_at: item.received_at ?? new Date().toISOString() };
}

function formatTime(value: string) {
  if (!value) return new Date().toLocaleTimeString();
  return new Date(value).toLocaleTimeString();
}

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : "Có lỗi xảy ra";
}
