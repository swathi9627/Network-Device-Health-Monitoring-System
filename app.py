import platform
import random
import re
import socket
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import psutil
import streamlit as st

import snmplite

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False

# =====================================================
# 1. APP CONFIGURATION
# =====================================================
st.set_page_config(page_title="Network Health Monitor",
                   page_icon="🌐", layout="wide")
st.title("🌐 Network Device Health Monitoring System")
st.caption("Availability, CPU/memory, connectivity, AI anomaly detection, "
           "failure prediction and fault alerts for routers, switches and servers")

DB_PATH = Path(__file__).with_name("network_monitor_v2.db")
PING_TIMEOUT_MS = 2000
DEVICE_TYPES = ["Router", "Switch", "Server"]
MODES = ["Simulated", "Real ping", "TCP port", "SNMP"]
PROFILES = {"Router": {"cpu": 30, "mem": 45, "lat": 5},
            "Switch": {"cpu": 15, "mem": 35, "lat": 2},
            "Server": {"cpu": 45, "mem": 65, "lat": 10}}
OID_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_CPU = "1.3.6.1.2.1.25.3.3.1.2.1"
OID_MEM_TOTAL = "1.3.6.1.4.1.2021.4.5.0"
OID_MEM_AVAIL = "1.3.6.1.4.1.2021.4.6.0"
STATUS_LABEL = {"Up": "🟢 Up", "Warning": "🟡 Warning",
                "Down": "🔴 Down", "Unknown": "⚪ Unknown"}


def has(v):
    return v is not None and not (isinstance(v, float) and np.isnan(v))


# =====================================================
# 2. DATABASE
# =====================================================
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialize_database():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            host TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            mode TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device TEXT NOT NULL, host TEXT, type TEXT,
            status TEXT NOT NULL,
            cpu REAL, memory REAL, latency REAL, health REAL,
            checked_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device TEXT NOT NULL, severity TEXT NOT NULL,
            source TEXT NOT NULL, alert TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            acknowledged INTEGER NOT NULL DEFAULT 0)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_dev "
                     "ON samples(device, id)")

        if conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO devices (name, host, type, mode) VALUES (?,?,?,?)",
                [("Core Router R1", "10.0.0.1", "Router", "Simulated"),
                 ("Access Switch SW1", "10.0.1.1", "Switch", "Simulated"),
                 ("Web Server SRV1", "10.0.2.10", "Server", "Simulated"),
                 ("Database Server SRV2", "10.0.2.20", "Server", "Simulated"),
                 ("Default Gateway", "10.12.128.1", "Router", "Real ping"),
                 ("Public DNS (Cloudflare)", "1.1.1.1", "Server", "Real ping"),
                 ("Laptop SNMP Agent", "127.0.0.1:1161", "Server", "SNMP")])

        cutoff = (datetime.now() - timedelta(days=7)).isoformat(timespec="seconds")
        conn.execute("DELETE FROM samples WHERE checked_at < ?", (cutoff,))


initialize_database()


def get_devices():
    with db() as conn:
        return pd.read_sql_query(
            "SELECT id, name, host, type, mode FROM devices ORDER BY id", conn)


def add_device(name, host, dtype, mode):
    with db() as conn:
        conn.execute("INSERT INTO devices (name, host, type, mode) "
                     "VALUES (?,?,?,?)", (name, host, dtype, mode))


def remove_device(device_id):
    with db() as conn:
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))


def save_sample(row):
    with db() as conn:
        conn.execute("""INSERT INTO samples
            (device, host, type, status, cpu, memory, latency, health, checked_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
                     (row["Device"], row["Host"], row["Type"], row["Status"],
                      row["CPU Usage (%)"], row["Memory Usage (%)"],
                      row["Latency (ms)"], row["Health Score"],
                      row["Checked At"]))


def get_last_status(device):
    with db() as conn:
        r = conn.execute("SELECT status FROM samples WHERE device=? "
                         "ORDER BY id DESC LIMIT 1", (device,)).fetchone()
    return r[0] if r else None


def get_recent(device, n=60):
    with db() as conn:
        df = pd.read_sql_query(
            "SELECT cpu, memory, latency, health, status, checked_at "
            "FROM samples WHERE device=? ORDER BY id DESC LIMIT ?",
            conn, params=(device, n))
    df = df.iloc[::-1].reset_index(drop=True)
    df["checked_at"] = pd.to_datetime(df["checked_at"])
    return df


def get_export(limit=5000):
    with db() as conn:
        return pd.read_sql_query(
            "SELECT device, host, type, status, cpu, memory, latency, health, "
            "checked_at FROM samples ORDER BY id DESC LIMIT ?",
            conn, params=(limit,))


def get_availability():
    cutoff = (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds")
    with db() as conn:
        rows = conn.execute("""
            SELECT device,
                   100.0 * AVG(CASE WHEN status IN ('Up','Warning')
                               THEN 1.0 ELSE 0.0 END)
            FROM samples
            WHERE checked_at >= ? AND status != 'Unknown'
            GROUP BY device""", (cutoff,)).fetchall()
    return {d: round(a, 1) for d, a in rows}


def save_alert(device, severity, source, message, checked_at):
    """Skip identical alerts raised in the last 5 minutes."""
    cutoff = (datetime.now() - timedelta(minutes=5)).isoformat(timespec="seconds")
    with db() as conn:
        recent = conn.execute("""SELECT id FROM alert_history
            WHERE device=? AND severity=? AND alert=? AND occurred_at>=?
            LIMIT 1""", (device, severity, message, cutoff)).fetchone()
        if recent is None:
            conn.execute("""INSERT INTO alert_history
                (device, severity, source, alert, occurred_at)
                VALUES (?,?,?,?,?)""",
                         (device, severity, source, message, checked_at))


def get_alert_history(limit=500):
    with db() as conn:
        return pd.read_sql_query(
            "SELECT device, severity, source, alert, occurred_at, acknowledged "
            "FROM alert_history ORDER BY id DESC LIMIT ?", conn, params=(limit,))


def active_alert_count():
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM alert_history "
                            "WHERE acknowledged=0").fetchone()[0]


def acknowledge_all():
    with db() as conn:
        conn.execute("UPDATE alert_history SET acknowledged=1 "
                     "WHERE acknowledged=0")


# =====================================================
# 3. SIDEBAR: SETTINGS, DEVICES, FAULT INJECTION
# =====================================================
st.sidebar.header("⚙️ Monitoring Settings")
paused = st.sidebar.checkbox("Pause monitoring", value=False)
interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 15)
CPU_LIMIT = st.sidebar.slider("CPU threshold (%)", 50, 95, 80)
MEMORY_LIMIT = st.sidebar.slider("Memory threshold (%)", 50, 95, 85)
LATENCY_LIMIT = st.sidebar.slider("Latency threshold (ms)", 20, 500, 150)

st.sidebar.divider()
st.sidebar.header("🖧 Devices")

with st.sidebar.form("add_device_form", clear_on_submit=True):
    new_name = st.text_input("Device name")
    new_host = st.text_input("IP address or hostname")
    new_type = st.selectbox("Device type", DEVICE_TYPES)
    new_mode = st.selectbox("Monitoring mode", MODES,
                            help="Simulated = generated metrics. Real ping = ICMP. "
                                 "TCP port = host:port service check. "
                                 "SNMP = real CPU/memory via SNMP (host or host:port).")
    if st.form_submit_button("Add device"):
        name, host = new_name.strip(), new_host.strip()
        if not name or not host:
            st.sidebar.error("Enter both a name and a host.")
        elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-:]*", host):
            st.sidebar.error("Invalid host format.")
        else:
            try:
                add_device(name, host, new_type, new_mode)
                st.sidebar.success(f"Added {name}.")
            except sqlite3.IntegrityError:
                st.sidebar.error("That name or host already exists.")

configured = get_devices()
if not configured.empty:
    options = {f'{r["name"]} — {r["host"]}': int(r["id"])
               for _, r in configured.iterrows()}
    sel = st.sidebar.selectbox("Select a device to remove", list(options))
    if st.sidebar.button("Remove selected device"):
        remove_device(options[sel])
        st.rerun()


def sim_state(name, dtype="Server"):
    sims = st.session_state.setdefault("sim", {})
    if name not in sims:
        p = PROFILES.get(dtype, PROFILES["Server"])
        sims[name] = {"cpu": p["cpu"], "mem": p["mem"], "lat": p["lat"],
                      "base": p, "fault": None, "ttl": 0}
    return sims[name]


sim_names = configured[configured["mode"] == "Simulated"]["name"].tolist()
if sim_names:
    st.sidebar.divider()
    st.sidebar.header("💥 Fault Injection (demo)")
    fault_dev = st.sidebar.selectbox("Simulated device", sim_names, key="fault_dev")
    fault_kind = st.sidebar.selectbox(
        "Fault type", ["down", "cpu", "memory", "latency"], key="fault_kind")
    if st.sidebar.button("Inject fault"):
        dtype = configured.loc[configured["name"] == fault_dev, "type"].iloc[0]
        s = sim_state(fault_dev, dtype)
        s["fault"], s["ttl"] = fault_kind, 5
        st.sidebar.warning(f"Fault '{fault_kind}' injected on {fault_dev}.")

# =====================================================
# 4. DATA SOURCES: REAL PING AND SIMULATOR
# =====================================================
def ping_host(host):
    """Cross-platform ICMP ping. Returns (reachability, latency_ms)."""
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, PING_TIMEOUT_MS // 1000)), host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=5)
        out = r.stdout + r.stderr
        m = re.search(r"time\s*[=<]\s*([\d.]+)\s*ms", out, re.IGNORECASE)
        # "ttl" must appear: Windows can return code 0 for 'host unreachable'
        if r.returncode == 0 and "ttl" in out.lower():
            return "Reachable", (float(m.group(1)) if m else None)
        return "Unreachable", None
    except (subprocess.TimeoutExpired, OSError):
        return "Check failed", None


def tcp_check(host, port, timeout=2):
    """Check whether a service accepts connections. Returns (reach, latency_ms)."""
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "Reachable", round((time.time() - start) * 1000, 1)
    except OSError:
        return "Unreachable", None


def split_host_port(host, default_port):
    h, sep, p = host.rpartition(":")
    if sep and h and p.isdigit():
        return h, int(p)
    return host, default_port


def snmp_check(host):
    """Poll a device over SNMP. Returns (reach, cpu, mem, latency_ms)."""
    h, port = split_host_port(host, 161)
    start = time.time()
    try:
        r = snmplite.get(h, [OID_UPTIME, OID_CPU, OID_MEM_TOTAL, OID_MEM_AVAIL],
                         port=port, timeout=2)
    except (OSError, ValueError, IndexError):
        return "Unreachable", None, None, None
    lat = round((time.time() - start) * 1000, 1)
    cpu, tot, avail = r.get(OID_CPU), r.get(OID_MEM_TOTAL), r.get(OID_MEM_AVAIL)
    mem = None
    if isinstance(tot, int) and isinstance(avail, int) and tot > 0:
        mem = round(100.0 * (tot - avail) / tot, 1)
    cpu = float(cpu) if isinstance(cpu, int) else None
    return "Reachable", cpu, mem, lat


def check_real(d):
    """Returns (reach, cpu, mem, latency) for Real ping / TCP port / SNMP."""
    host, mode = str(d["host"]).strip(), d["mode"]
    if mode == "SNMP":
        return snmp_check(host)
    if mode == "TCP port":
        h, port = split_host_port(host, 0)
        if port == 0:
            return "Check failed", None, None, None
        reach, lat = tcp_check(h, port)
    else:
        reach, lat = ping_host(host)
    return reach, None, None, lat


def simulate(name, dtype="Server"):
    """Random-walk metrics around the device type's baseline."""
    s = sim_state(name, dtype)
    b = s["base"]
    if s["fault"] is None and random.random() < 0.03:
        s["fault"] = random.choice(["down", "cpu", "memory", "latency"])
        s["ttl"] = random.randint(3, 6)

    s["cpu"] = float(np.clip(s["cpu"] + (b["cpu"] - s["cpu"]) * 0.2 + random.gauss(0, 3), 3, 75))
    s["mem"] = float(np.clip(s["mem"] + (b["mem"] - s["mem"]) * 0.1 + random.gauss(0, 1.5), 20, 80))
    s["lat"] = float(np.clip(s["lat"] + (b["lat"] - s["lat"]) * 0.3 + random.gauss(0, 2), 1, 60))
    cpu, mem, lat, reach = s["cpu"], s["mem"], s["lat"], "Reachable"

    f = s["fault"]
    if f == "down":
        reach, cpu, mem, lat = "Unreachable", None, None, None
    elif f == "cpu":
        cpu = random.uniform(90, 99)
    elif f == "memory":
        mem = random.uniform(90, 98)
    elif f == "latency":
        lat = random.uniform(200, 400)
    if f:
        s["ttl"] -= 1
        if s["ttl"] <= 0:
            s["fault"] = None

    r1 = lambda v: round(v, 1) if v is not None else None
    return reach, r1(cpu), r1(mem), r1(lat)


# =====================================================
# 5. RULES AND HEALTH SCORE
# =====================================================
def threshold_alerts(row):
    out = []
    reach = row["Reachability"]
    if reach == "Unreachable":
        out.append(("Critical", "Reachability", "Device unreachable - no response"))
    elif reach == "Check failed":
        out.append(("Warning", "Reachability", "Connectivity check could not be completed"))
    checks = [("CPU", "CPU Usage (%)", CPU_LIMIT, 95),
              ("Memory", "Memory Usage (%)", MEMORY_LIMIT, 95),
              ("Latency", "Latency (ms)", LATENCY_LIMIT, LATENCY_LIMIT * 2)]
    for label, col, limit, crit in checks:
        v = row[col]
        if has(v) and v > limit:
            sev = "Critical" if v >= crit else "Warning"
            out.append((sev, "Threshold", f"{label} above threshold ({limit})"))
    return out


def health_score(status, cpu, mem, lat):
    if status == "Down":
        return 0.0
    if status == "Unknown":
        return None
    parts = []
    for v, lim, w in [(cpu, CPU_LIMIT, 35), (mem, MEMORY_LIMIT, 35),
                      (lat, LATENCY_LIMIT, 30)]:
        if has(v):
            frac = min(max((v - 0.5 * lim) / (0.5 * lim), 0), 1)
            parts.append((frac, w))
    if not parts:
        return 100.0
    penalty = sum(f * w for f, w in parts) / sum(w for _, w in parts)
    return round(100 * (1 - penalty), 1)


def make_row(name, host, dtype, mode, reach, cpu, mem, lat, checked_at):
    row = {"Device": name, "Host": host, "Type": dtype, "Mode": mode,
           "Reachability": reach, "CPU Usage (%)": cpu,
           "Memory Usage (%)": mem, "Latency (ms)": lat,
           "Checked At": checked_at}
    th = threshold_alerts(row)
    if reach == "Unreachable":
        status = "Down"
    elif reach == "Check failed":
        status = "Unknown"
    elif any(src == "Threshold" for _, src, _ in th):
        status = "Warning"
    else:
        status = "Up"
    row["Status"] = status
    row["Health Score"] = health_score(status, cpu, mem, lat)
    return row, th


# =====================================================
# 6. AI LAYER
# =====================================================
def zscore_anomaly(history_values, value, window=40, z_limit=3.0):
    """Compare a new value with the device's own recent baseline."""
    vals = np.array([v for v in history_values if has(v)][-window:], dtype=float)
    if len(vals) < 15:
        return None
    mu = vals.mean()
    sd = max(vals.std(), 2.0, 0.05 * abs(mu))   # floor avoids false alarms
    z = (value - mu) / sd
    return z if abs(z) >= z_limit else None


def forecast_breach(minutes, values, limit, horizon_min=30):
    """Fit a line to recent values and estimate minutes until the limit."""
    x, y = np.array(minutes, dtype=float), np.array(values, dtype=float)
    if len(y) < 10 or np.std(y) < 1e-9:
        return None
    if np.corrcoef(x, y)[0, 1] < 0.7:            # trend must be convincing
        return None
    slope, intercept = np.polyfit(x, y, 1)
    if slope <= 0 or intercept >= limit:
        return None
    eta = (limit - intercept) / slope            # x = 0 is "now"
    return eta if eta <= horizon_min else None


def isolation_forest_flag(hist, row):
    """Flag an unusual COMBINATION of metrics (multivariate anomaly)."""
    if not SKLEARN_OK:
        return False
    cols = [("cpu", "CPU Usage (%)"), ("memory", "Memory Usage (%)"),
            ("latency", "Latency (ms)")]
    use = [(h, r) for h, r in cols
           if has(row[r]) and hist[h].notna().sum() >= 60]
    if len(use) < 2:
        return False
    data = hist[[h for h, _ in use]].dropna()
    if len(data) < 60:
        return False
    model = IsolationForest(n_estimators=100, contamination=0.02,
                            random_state=42).fit(data.values)
    x = np.array([[row[r] for _, r in use]], dtype=float)
    return model.predict(x)[0] == -1


def run_ai(row, hist):
    out = []
    if row["Status"] in ("Down", "Unknown"):
        return out
    now = pd.to_datetime(row["Checked At"])
    metrics = [("CPU", "CPU Usage (%)", "cpu", CPU_LIMIT, "%"),
               ("Memory", "Memory Usage (%)", "memory", MEMORY_LIMIT, "%"),
               ("Latency", "Latency (ms)", "latency", LATENCY_LIMIT, " ms")]
    for label, col, hcol, limit, unit in metrics:
        v = row[col]
        if not has(v):
            continue
        if zscore_anomaly(hist[hcol].tolist(), v) is not None:
            out.append(("Warning", "AI Anomaly",
                        f"{label} anomaly: deviates from learned baseline"))
        recent = hist[["checked_at", hcol]].dropna().tail(19)
        if len(recent) >= 9 and v < limit:
            mins = ((recent["checked_at"] - now).dt.total_seconds() / 60).tolist() + [0.0]
            vals = recent[hcol].tolist() + [float(v)]
            eta = forecast_breach(mins, vals, limit)
            if eta is not None:
                bucket = int(np.ceil(max(eta, 0.1) / 5) * 5)
                out.append(("Warning", "AI Prediction",
                            f"{label} trending up; predicted to cross "
                            f"{limit}{unit} in ~{bucket} min"))
    if isolation_forest_flag(hist, row):
        out.append(("Warning", "AI Anomaly",
                    "Unusual combination of metrics (Isolation Forest)"))
    return out


# =====================================================
# 7. COLLECTION CYCLE
# =====================================================
def collect_metrics():
    checked_at = datetime.now().isoformat(timespec="seconds")
    rows = []

    # Real CPU/memory of this computer
    cpu = round(float(psutil.cpu_percent(interval=0.5)), 1)
    mem = round(float(psutil.virtual_memory().percent), 1)
    rows.append(make_row(platform.node() or "Local Computer", "localhost",
                         "Server", "Local (psutil)", "Reachable",
                         cpu, mem, None, checked_at))

    devices = get_devices()
    real = []
    for _, d in devices.iterrows():
        if d["mode"] == "Simulated":
            reach, c, m, l = simulate(d["name"], d["type"])
            rows.append(make_row(d["name"], d["host"], d["type"], "Simulated",
                                 reach, c, m, l, checked_at))
        else:
            real.append(d)

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(check_real, real))
    for d, (reach, c, m, lat) in zip(real, results):
        rows.append(make_row(d["name"], d["host"], d["type"], d["mode"],
                             reach, c, m, lat, checked_at))

    all_alerts = []
    final_rows = []
    for row, th in rows:
        name = row["Device"]
        prev = get_last_status(name)
        hist = get_recent(name, 60)
        alerts = th + run_ai(row, hist)
        if prev == "Down" and row["Status"] in ("Up", "Warning"):
            alerts.append(("Info", "Recovery", "Device recovered and is reachable again"))
        save_sample(row)
        for sev, src, msg in alerts:
            save_alert(name, sev, src, msg, checked_at)
            all_alerts.append({"Device": name, "Severity": sev,
                               "Source": src, "Alert": msg})
        final_rows.append(row)

    return pd.DataFrame(final_rows), all_alerts


# =====================================================
# 8. DASHBOARD
# =====================================================
def live_dashboard():
    with st.spinner("Checking devices and running AI analysis..."):
        df, current_alerts = collect_metrics()

    avail = get_availability()
    df["Availability 24h (%)"] = df["Device"].map(avail)
    df["State"] = df["Status"].map(STATUS_LABEL)

    up = int((df["Status"] == "Up").sum())
    warn = int((df["Status"] == "Warning").sum())
    down = int((df["Status"] == "Down").sum())
    avg_health = df["Health Score"].mean()

    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Devices", len(df))
    k2.metric("🟢 Up", up)
    k3.metric("🟡 Warning", warn)
    k4.metric("🔴 Down", down)
    k5.metric("Avg Health", f"{avg_health:.0f}/100" if pd.notna(avg_health) else "n/a")
    k6.metric("Unacknowledged Alerts", active_alert_count())
    st.caption("Last check: " + datetime.now().strftime("%d %b %Y, %H:%M:%S"))

    t_status, t_perf, t_ai, t_alerts, t_hist = st.tabs(
        ["📟 Device Status", "📊 Performance", "🤖 AI Insights",
         "🚨 Alerts", "📈 History & Export"])

    # ---------- Device status ----------
    with t_status:
        st.dataframe(
            df[["Device", "Host", "Type", "Mode", "State", "CPU Usage (%)",
                "Memory Usage (%)", "Latency (ms)", "Health Score",
                "Availability 24h (%)", "Checked At"]],
            use_container_width=True, hide_index=True,
            column_config={
                "CPU Usage (%)": st.column_config.ProgressColumn(
                    "CPU (%)", min_value=0, max_value=100, format="%.1f"),
                "Memory Usage (%)": st.column_config.ProgressColumn(
                    "Memory (%)", min_value=0, max_value=100, format="%.1f"),
                "Health Score": st.column_config.ProgressColumn(
                    "Health", min_value=0, max_value=100, format="%.0f"),
                "Availability 24h (%)": st.column_config.NumberColumn(
                    "Availability 24h", format="%.1f%%"),
            })
        st.caption("Simulated devices generate CPU/memory/latency; real targets "
                   "are checked by ping. A failed ping does not always mean the "
                   "device is off, since firewalls may block ICMP. SNMP-mode devices "
                   "report real CPU/memory.")

    # ---------- Performance ----------
    with t_perf:
        perf = df.melt(id_vars="Device",
                       value_vars=["CPU Usage (%)", "Memory Usage (%)"],
                       var_name="Metric", value_name="Usage (%)"
                       ).dropna(subset=["Usage (%)"])
        if not perf.empty:
            fig = px.bar(perf, x="Device", y="Usage (%)", color="Metric",
                         barmode="group", range_y=[0, 100],
                         title="CPU and Memory Utilization")
            fig.add_hline(y=CPU_LIMIT, line_dash="dash",
                          annotation_text="CPU limit")
            fig.add_hline(y=MEMORY_LIMIT, line_dash="dot",
                          annotation_text="Memory limit")
            st.plotly_chart(fig, use_container_width=True, key="perf_cpu_mem")

        lat = df.dropna(subset=["Latency (ms)"])
        if not lat.empty:
            lf = px.bar(lat, x="Device", y="Latency (ms)",
                        title="Latency (ms)")
            lf.add_hline(y=LATENCY_LIMIT, line_dash="dash",
                         annotation_text="Latency limit")
            st.plotly_chart(lf, use_container_width=True, key="perf_lat")

    # ---------- AI insights ----------
    with t_ai:
        st.markdown(
            "**Methods used:** (1) rolling z-score anomaly detection per metric, "
            "(2) Isolation Forest on combined CPU/memory/latency"
            + ("" if SKLEARN_OK else " *(install scikit-learn to enable)*")
            + ", (3) linear-trend forecasting to predict threshold breaches, "
            "(4) a 0-100 health score."
        )
        ai_now = [a for a in current_alerts
                  if a["Source"] in ("AI Anomaly", "AI Prediction")]
        if ai_now:
            st.dataframe(pd.DataFrame(ai_now), use_container_width=True,
                         hide_index=True)
        else:
            st.success("AI found no anomalies or predicted breaches in this check.")

        hs = df.dropna(subset=["Health Score"]).sort_values("Health Score")
        if not hs.empty:
            hf = px.bar(hs, x="Device", y="Health Score", range_y=[0, 100],
                        color="Health Score", color_continuous_scale="RdYlGn",
                        title="Device Health Score (lower = needs attention)")
            st.plotly_chart(hf, use_container_width=True, key="ai_health")

        c1, c2 = st.columns(2)
        dev = c1.selectbox("Device", df["Device"].tolist(), key="ai_dev")
        metric = c2.selectbox("Metric", ["cpu", "memory", "latency"],
                              key="ai_metric")
        h = get_recent(dev, 300).dropna(subset=[metric]).reset_index(drop=True)
        if len(h) < 20:
            st.info("Collecting more data (needs about 20 samples)...")
        else:
            s = h[metric]
            base = s.shift(1).rolling(40, min_periods=15)
            mu, sd = base.mean(), base.std().fillna(0)
            floor = (mu.abs() * 0.05).clip(lower=2.0)
            sd = sd.where(sd > floor, floor)
            flagged = h[((s - mu).abs() / sd) >= 3]
            fig = px.line(h, x="checked_at", y=metric, markers=True,
                          title=f"{metric.upper()} with AI-detected anomalies "
                                f"- {dev}")
            fig.add_trace(go.Scatter(
                x=flagged["checked_at"], y=flagged[metric], mode="markers",
                marker=dict(color="red", size=11), name="Anomaly"))
            st.plotly_chart(fig, use_container_width=True, key="ai_anom_chart")

    # ---------- Alerts ----------
    with t_alerts:
        st.subheader("Alerts from this check")
        if current_alerts:
            st.dataframe(pd.DataFrame(current_alerts),
                         use_container_width=True, hide_index=True)
        else:
            st.success("No alerts in the latest check.")

        st.subheader("Alert history")
        ah = get_alert_history()
        if ah.empty:
            st.info("No alerts recorded yet.")
        else:
            sev = st.multiselect("Filter severity",
                                 ["Critical", "Warning", "Info"],
                                 default=["Critical", "Warning", "Info"],
                                 key="sev_filter")
            view = ah[ah["severity"].isin(sev)].copy()
            view["acknowledged"] = view["acknowledged"].map({0: "No", 1: "Yes"})
            st.dataframe(view, use_container_width=True, hide_index=True)
            b1, b2 = st.columns(2)
            if b1.button("✅ Acknowledge all alerts", key="ack_btn"):
                acknowledge_all()
                st.rerun(scope="fragment")
            b2.download_button("Download alert history (CSV)",
                               ah.to_csv(index=False).encode("utf-8"),
                               "network_alert_history.csv", "text/csv",
                               key="dl_alerts")

    # ---------- History ----------
    with t_hist:
        hd = st.selectbox("Device", df["Device"].tolist(), key="hist_dev")
        h = get_recent(hd, 500)
        for col, title, limit in [("cpu", "CPU Usage (%)", CPU_LIMIT),
                                  ("memory", "Memory Usage (%)", MEMORY_LIMIT),
                                  ("latency", "Latency (ms)", LATENCY_LIMIT),
                                  ("health", "Health Score", None)]:
            d = h.dropna(subset=[col])
            if not d.empty:
                f = px.line(d, x="checked_at", y=col, markers=True,
                            title=f"{title} - {hd}")
                if limit is not None:
                    f.add_hline(y=limit, line_dash="dash",
                                annotation_text="threshold")
                st.plotly_chart(f, use_container_width=True, key=f"hist_{col}")
        exp = get_export()
        st.download_button("Download all measurements (CSV)",
                           exp.to_csv(index=False).encode("utf-8"),
                           "network_monitor_history.csv", "text/csv",
                           key="dl_hist")


run_every = None if paused else f"{interval}s"
st.fragment(run_every=run_every)(live_dashboard)()

with st.expander("About this system"):
    st.write("""
    - **Real data:** CPU/memory of this computer (psutil), ICMP ping, TCP
      port checks, and **SNMP v2c polling** (CPU, memory, uptime).
    - **Simulated data:** routers, switches and servers with realistic metric
      drift and random or injected faults (allowed by the assignment).
    - **Storage:** SQLite keeps samples (7 days), alerts and device inventory.
    - **AI:** z-score anomaly detection, Isolation Forest, linear forecasting
      and a health score.
    - **SNMP:** built-in manager (`snmplite.py`) polls any SNMP agent; run
      `snmpagent.py` to expose this laptop's real CPU/memory over SNMP.
    """)