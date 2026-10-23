"""
app.py — SentinelAI Streamlit Dashboard

Real-time cybersecurity incident triage and remediation UI powered by
Gemini AI. Provides incident log ingestion, AI-driven threat analysis,
chain-of-thought reasoning display, and remediation consoles.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from agent_engine import (
    IncidentReport,
    RateLimitError,
    SanitizationError,
    TokenBucket,
    analyze_incident,
)
from mock_logs import (
    ALL_SCENARIOS,
    get_scenario,
    get_scenario_label,
    get_scenario_names,
)

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

load_dotenv()

st.set_page_config(
    page_title="SentinelAI — Incident Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/yourorg/sentinel-ai-agent",
        "Report a bug": "https://github.com/yourorg/sentinel-ai-agent/issues",
        "About": "SentinelAI — Autonomous Cybersecurity Incident Triage powered by Gemini.",
    },
)

# ---------------------------------------------------------------------------
# Custom CSS — Dark security theme
# ---------------------------------------------------------------------------

st.markdown(
    """
<style>
/* ---- Global dark palette ---- */
[data-testid="stAppViewContainer"] {
    background: #0d1117;
    color: #c9d1d9;
}
[data-testid="stSidebar"] {
    background: #161b22;
    border-right: 1px solid #30363d;
}
[data-testid="stHeader"] { background: transparent; }

/* ---- Metric cards ---- */
[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px 16px;
}

/* ---- Tab styling ---- */
button[data-baseweb="tab"] {
    font-weight: 600;
    letter-spacing: 0.03em;
}

/* ---- Code blocks ---- */
.stCode { border-radius: 6px; }

/* ---- Severity badges ---- */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}
.badge-critical { background: #b91c1c; color: #fee2e2; }
.badge-high     { background: #c2410c; color: #ffedd5; }
.badge-medium   { background: #92400e; color: #fef3c7; }
.badge-low      { background: #065f46; color: #d1fae5; }
.badge-info     { background: #1e3a5f; color: #bfdbfe; }

/* ---- CoT step cards ---- */
.cot-step {
    background: #161b22;
    border-left: 3px solid #388bfd;
    border-radius: 4px;
    padding: 10px 14px;
    margin-bottom: 8px;
    font-size: 0.92rem;
}
.evidence-pill {
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 4px;
    padding: 6px 10px;
    margin: 4px 0;
    font-family: monospace;
    font-size: 0.82rem;
    color: #6ee7b7;
    word-break: break-all;
}

/* ---- Escalation banner ---- */
.escalation-banner {
    background: linear-gradient(135deg, #7f1d1d, #991b1b);
    border: 1px solid #ef4444;
    border-radius: 8px;
    padding: 16px 20px;
    margin: 12px 0;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { border-color: #ef4444; }
    50%       { border-color: #fca5a5; }
}

/* ---- Action checklist ---- */
.action-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 8px 0;
    border-bottom: 1px solid #21262d;
}
.action-num {
    background: #1d4ed8;
    color: white;
    border-radius: 50%;
    width: 22px; height: 22px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
    font-weight: 700;
    flex-shrink: 0;
}

/* ---- Rate limit badge ---- */
.rate-ok   { color: #34d399; }
.rate-warn { color: #fbbf24; }
.rate-bad  { color: #f87171; }
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Session State Initialisation
# ---------------------------------------------------------------------------

def _init_session_state() -> None:
    defaults: dict = {
        "rate_limiter": TokenBucket(capacity=10, refill_rate=10 / 60),
        "incident_history": [],          # list[dict] for history tab
        "last_report": None,             # IncidentReport | None
        "last_scenario": None,           # str | None
        "analysis_count": 0,
        "escalation_count": 0,
        "total_threat_score": 0.0,
        "active_tab": 0,
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default


_init_session_state()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_BADGE_CLASS = {
    "CRITICAL":     "badge-critical",
    "HIGH":         "badge-high",
    "MEDIUM":       "badge-medium",
    "LOW":          "badge-low",
    "INFORMATIONAL": "badge-info",
}

_SEVERITY_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "INFORMATIONAL": "#3b82f6",
}

_MODEL_OPTIONS = [
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
]


def _severity_badge(label: str) -> str:
    cls = _SEVERITY_BADGE_CLASS.get(label.upper(), "badge-info")
    return f'<span class="badge {cls}">{label.upper()}</span>'


def _cvss_color(score: float) -> str:
    if score >= 9.0:
        return "#ef4444"
    if score >= 7.0:
        return "#f97316"
    if score >= 4.0:
        return "#eab308"
    return "#22c55e"


def _avg_threat_score() -> float:
    if st.session_state.analysis_count == 0:
        return 0.0
    return st.session_state.total_threat_score / st.session_state.analysis_count


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def render_sidebar() -> tuple[str, str]:
    """Render sidebar controls. Returns (api_key, model_name)."""
    with st.sidebar:
        st.markdown("## 🛡️ SentinelAI")
        st.markdown("*Autonomous Cyber Incident Triage*")
        st.divider()

        # API Key
        st.markdown("### 🔑 Gemini API Key")
        env_key = os.getenv("GOOGLE_API_KEY", "")
        api_key = st.text_input(
            "API Key",
            value=env_key,
            type="password",
            placeholder="AIza...",
            help="Your Google Generative AI API key. Set GOOGLE_API_KEY in .env to pre-fill.",
            label_visibility="collapsed",
        )
        if not api_key:
            st.warning("⚠️ Enter your Gemini API key to enable analysis.")
        else:
            st.success("✅ API key configured")

        st.divider()

        # Model selector
        st.markdown("### 🤖 Model")
        model_name = st.selectbox(
            "Gemini Model",
            options=_MODEL_OPTIONS,
            index=0,
            help="gemini-2.5-flash is recommended for speed. Use pro for deeper analysis.",
            label_visibility="collapsed",
        )

        st.divider()

        # Rate limit status
        st.markdown("### ⚡ Rate Limit")
        rl = st.session_state.rate_limiter
        tokens = rl.available_tokens
        pct = int(tokens / rl.capacity * 100)

        if pct >= 60:
            cls = "rate-ok"
            icon = "🟢"
        elif pct >= 20:
            cls = "rate-warn"
            icon = "🟡"
        else:
            cls = "rate-bad"
            icon = "🔴"

        st.markdown(
            f'<span class="{cls}">{icon} {tokens}/{rl.capacity} tokens available</span>',
            unsafe_allow_html=True,
        )
        st.progress(pct / 100)
        st.caption("Resets at 10 req / minute")

        st.divider()

        # Security notice
        st.markdown(
            """
            <div style="font-size:0.75rem; color:#6e7681; line-height:1.5">
            ⚠️ <strong>Security Notice</strong><br>
            Remediation scripts are <em>for review only</em>.<br>
            Never execute without analyst approval.<br>
            Logs are processed via Gemini API —
            do not submit production PII.
            </div>
            """,
            unsafe_allow_html=True,
        )

    return api_key, model_name


# ---------------------------------------------------------------------------
# Top Metrics Strip
# ---------------------------------------------------------------------------

def render_metrics() -> None:
    """Render the real-time metrics bar at the top of the page."""
    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.metric(
            label="🔍 Total Incidents Analysed",
            value=st.session_state.analysis_count,
        )
    with c2:
        avg = _avg_threat_score()
        st.metric(
            label="📊 Avg CVSS Score",
            value=f"{avg:.1f}" if avg else "—",
            delta=None,
        )
    with c3:
        st.metric(
            label="🚨 Escalations Triggered",
            value=st.session_state.escalation_count,
        )
    with c4:
        rl = st.session_state.rate_limiter
        st.metric(
            label="⚡ API Tokens Remaining",
            value=f"{rl.available_tokens}/{rl.capacity}",
        )
    with c5:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        st.metric(label="🕐 Current Time", value=ts)


# ---------------------------------------------------------------------------
# Tab 1 — Incident Input
# ---------------------------------------------------------------------------

def render_input_tab(api_key: str, model_name: str) -> None:
    """Render the incident log ingestion and analysis trigger tab."""
    st.markdown("### 📥 Incident Log Input")
    st.markdown("Load a mock scenario or paste raw log data for AI-powered triage.")

    col_left, col_right = st.columns([1, 2], gap="large")

    with col_left:
        st.markdown("#### Incident Parameters")

        input_mode = st.radio(
            "Input mode",
            ["📦 Load Mock Scenario", "📝 Paste Raw Logs"],
            horizontal=False,
        )

        scenario_key: str | None = None
        source_ip = "0.0.0.0"
        event_type = ""
        severity_hint = "HIGH"

        if input_mode == "📦 Load Mock Scenario":
            scenario_labels = {
                get_scenario_label(k): k for k in get_scenario_names()
            }
            selected_label = st.selectbox(
                "Select scenario",
                options=list(scenario_labels.keys()),
            )
            scenario_key = scenario_labels[selected_label]
            scenario_data = get_scenario(scenario_key)

            source_ip = scenario_data["source_ip"]
            event_type = scenario_data["event_type"]
            severity_hint = scenario_data["severity"]

            st.info(
                f"**ID:** {scenario_data['id']}  \n"
                f"**Source IP:** `{source_ip}`  \n"
                f"**Severity:** {scenario_data['severity']}  \n"
                f"**Assets at Risk:** {', '.join(scenario_data['affected_assets'][:2])}"
            )
            raw_log = scenario_data["raw_log"]

        else:
            source_ip = st.text_input(
                "Source / Attacker IP",
                value="192.168.1.100",
                placeholder="e.g. 185.220.101.47",
            )
            event_type = st.text_input(
                "Event Type",
                value="Suspicious Activity",
                placeholder="e.g. SSH Brute Force",
            )
            severity_hint = st.selectbox(
                "Analyst-assessed severity",
                ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                index=2,
            )
            raw_log = ""

        st.markdown("---")
        analyze_btn = st.button(
            "⚡ Analyze with SentinelAI",
            type="primary",
            use_container_width=True,
            disabled=not api_key,
        )

    with col_right:
        st.markdown("#### Log Preview")
        if input_mode == "📦 Load Mock Scenario":
            st.code(raw_log, language="text", line_numbers=True)
        else:
            raw_log = st.text_area(
                "Paste raw log data here",
                height=420,
                placeholder="Oct 23 07:00:01 server sshd[3821]: Failed password for root from 1.2.3.4...",
                label_visibility="collapsed",
            )

    # ---- Run analysis ----
    if analyze_btn:
        if not raw_log.strip():
            st.error("❌ Log data is empty. Please load a scenario or paste log content.")
            return
        if not api_key:
            st.error("❌ Gemini API key is required. Configure it in the sidebar.")
            return

        with st.spinner("🧠 SentinelAI is reasoning through the incident…"):
            try:
                report: IncidentReport = analyze_incident(
                    raw_log=raw_log,
                    source_ip=source_ip,
                    event_type=event_type,
                    severity_hint=severity_hint,
                    api_key=api_key,
                    model_name=model_name,
                    rate_limiter=st.session_state.rate_limiter,
                    scenario=scenario_key or "",
                )

                # Update session state
                st.session_state.last_report = report
                st.session_state.last_scenario = scenario_key
                st.session_state.analysis_count += 1
                st.session_state.total_threat_score += report.threat_assessment.cvss_estimate
                if report.remediation_plan.escalation_required:
                    st.session_state.escalation_count += 1

                # Add to history
                st.session_state.incident_history.append(
                    {
                        "Incident ID": report.incident_id,
                        "Timestamp": report.timestamp,
                        "Threat Type": report.threat_assessment.threat_type,
                        "Severity": report.threat_assessment.severity_label,
                        "CVSS": round(report.threat_assessment.cvss_estimate, 1),
                        "Confidence": f"{report.threat_assessment.confidence_score:.0%}",
                        "Escalation": "🚨 Yes" if report.remediation_plan.escalation_required else "No",
                        "TTM (min)": report.remediation_plan.estimated_ttm_minutes,
                    }
                )

                st.success(
                    f"✅ Analysis complete — Incident **{report.incident_id}** | "
                    f"CVSS: **{report.threat_assessment.cvss_estimate:.1f}** | "
                    f"Severity: **{report.threat_assessment.severity_label}**"
                )
                st.info("👆 Switch to the **AI Reasoning** or **Remediation Console** tabs to view results.")

            except SanitizationError as e:
                st.error(f"🛡️ **Input Blocked by Guardrails:** {e}")
            except RateLimitError as e:
                st.warning(f"⏱️ **Rate Limited:** {e}")
            except ValueError as e:
                st.error(f"❌ **Analysis Error:** {e}")
            except Exception as e:
                st.error(f"❌ **Unexpected Error:** {e}")


# ---------------------------------------------------------------------------
# Tab 2 — AI Reasoning Breakdown
# ---------------------------------------------------------------------------

def render_reasoning_tab() -> None:
    """Render the chain-of-thought reasoning and threat assessment tab."""
    report: IncidentReport | None = st.session_state.last_report

    if report is None:
        st.info("🔍 No analysis yet. Go to **Incident Input** and run an analysis.")
        return

    ta = report.threat_assessment
    cot = report.chain_of_thought

    # --- Threat overview bar ---
    st.markdown("### 🎯 Threat Assessment")
    o1, o2, o3, o4 = st.columns(4)

    with o1:
        st.markdown(
            f"<div style='text-align:center'>"
            f"<div style='font-size:2.5rem;font-weight:800;color:{_cvss_color(ta.cvss_estimate)}'>"
            f"{ta.cvss_estimate:.1f}</div>"
            f"<div style='color:#8b949e;font-size:0.85rem'>CVSS v3 Score</div></div>",
            unsafe_allow_html=True,
        )
    with o2:
        st.markdown(
            f"<div style='text-align:center'>"
            f"<div style='font-size:2rem;font-weight:700;color:#c9d1d9'>{ta.confidence_score:.0%}</div>"
            f"<div style='color:#8b949e;font-size:0.85rem'>AI Confidence</div></div>",
            unsafe_allow_html=True,
        )
    with o3:
        st.markdown(
            f"<div style='text-align:center'>"
            f"{_severity_badge(ta.severity_label)}"
            f"<div style='color:#8b949e;font-size:0.85rem;margin-top:6px'>Severity</div></div>",
            unsafe_allow_html=True,
        )
    with o4:
        st.markdown(
            f"<div style='text-align:center'>"
            f"<div style='font-size:1rem;font-weight:600;color:#c9d1d9'>{ta.attack_vector}</div>"
            f"<div style='color:#8b949e;font-size:0.85rem'>Attack Vector</div></div>",
            unsafe_allow_html=True,
        )

    st.divider()

    # --- CVSS progress bar ---
    st.markdown(f"**CVSS Score: {ta.cvss_estimate:.1f} / 10.0**")
    st.progress(ta.cvss_estimate / 10.0)

    # --- Threat details ---
    st.markdown(f"**Threat Type:** `{ta.threat_type}`")
    st.markdown("**Affected Assets:**")
    for asset in ta.affected_assets:
        st.markdown(f"- `{asset}`")

    st.divider()

    # --- Analyst summary ---
    st.markdown("### 📋 Executive Summary")
    st.info(report.analyst_notes)

    st.divider()

    # --- Chain of Thought ---
    st.markdown("### 🧠 Chain-of-Thought Reasoning")
    st.markdown(f"**Initial Hypothesis:** {cot.initial_hypothesis}")
    st.markdown(" ")

    st.markdown("**Reasoning Steps:**")
    for i, step in enumerate(cot.reasoning_steps, start=1):
        st.markdown(
            f'<div class="cot-step">🔹 <strong>Step {i}:</strong> {step}</div>',
            unsafe_allow_html=True,
        )

    st.markdown(" ")
    st.markdown("**Evidence Cited:**")
    for ev in cot.evidence_cited:
        st.markdown(
            f'<div class="evidence-pill">📎 {ev}</div>',
            unsafe_allow_html=True,
        )

    st.markdown(" ")
    st.markdown(
        f"**Final Verdict:** {cot.final_verdict}"
    )

    st.divider()

    # --- Raw JSON expander ---
    with st.expander("🔧 Raw IncidentReport JSON"):
        st.json(report.model_dump())


# ---------------------------------------------------------------------------
# Tab 3 — Remediation Console
# ---------------------------------------------------------------------------

def render_remediation_tab() -> None:
    """Render the remediation actions and patch script console."""
    report: IncidentReport | None = st.session_state.last_report

    if report is None:
        st.info("🔍 No analysis yet. Go to **Incident Input** and run an analysis.")
        return

    rp = report.remediation_plan

    # --- Escalation banner ---
    if rp.escalation_required:
        st.markdown(
            """
            <div class="escalation-banner">
            🚨 <strong style="font-size:1.1rem">ESCALATION REQUIRED</strong><br>
            This incident has been flagged for immediate escalation to senior security staff
            and/or management. Activate your Incident Response Plan (IRP) now.
            </div>
            """,
            unsafe_allow_html=True,
        )

    # --- TTM & metadata strip ---
    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("⏱️ Est. Time-to-Mitigate", f"{rp.estimated_ttm_minutes} min")
    with m2:
        st.metric("🔧 Immediate Actions", len(rp.immediate_actions))
    with m3:
        st.metric(
            "🚨 Escalation",
            "YES" if rp.escalation_required else "No",
            delta="URGENT" if rp.escalation_required else None,
            delta_color="inverse" if rp.escalation_required else "normal",
        )

    st.divider()

    # --- Immediate actions ---
    st.markdown("### ✅ Immediate Actions")
    for i, action in enumerate(rp.immediate_actions, start=1):
        st.markdown(
            f"""
            <div class="action-item">
              <span class="action-num">{i}</span>
              <span>{action}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # --- Patch script ---
    st.markdown("### 💻 Remediation Script")
    st.markdown(
        """
        <div style="background:#1a0000;border:1px solid #7f1d1d;border-radius:6px;
                    padding:10px 14px;margin-bottom:12px;font-size:0.85rem;color:#fca5a5">
        ⚠️ <strong>FOR REVIEW ONLY</strong> — This script has been generated by AI.
        Do <em>not</em> execute without thorough analyst review and change-management approval.
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.code(rp.patch_script, language="bash")

    st.divider()

    # --- Long-term recommendations ---
    st.markdown("### 🔭 Long-Term Recommendations")
    for rec in rp.long_term_recommendations:
        st.markdown(f"- {rec}")


# ---------------------------------------------------------------------------
# Tab 4 — Incident History
# ---------------------------------------------------------------------------

def render_history_tab() -> None:
    """Render the session incident history table with CSV export."""
    st.markdown("### 📜 Incident Analysis History")

    history = st.session_state.incident_history

    if not history:
        st.info("No incidents analysed in this session yet.")
        return

    df = pd.DataFrame(history)
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "CVSS": st.column_config.ProgressColumn(
                "CVSS",
                min_value=0,
                max_value=10,
                format="%.1f",
            ),
            "Escalation": st.column_config.TextColumn("Escalation"),
        },
    )

    # CSV export
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Export to CSV",
        data=csv,
        file_name=f"sentinelai_history_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        type="secondary",
    )

    st.divider()
    st.markdown("#### 📊 Session Summary")
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Total Incidents", len(history))
    s2.metric("Avg CVSS", f"{_avg_threat_score():.2f}")
    s3.metric("Escalations", st.session_state.escalation_count)
    s4.metric("Analyses Run", st.session_state.analysis_count)


# ---------------------------------------------------------------------------
# Main App Layout
# ---------------------------------------------------------------------------

def main() -> None:
    api_key, model_name = render_sidebar()

    # Page header
    st.markdown(
        """
        <div style="display:flex;align-items:center;gap:14px;margin-bottom:4px">
          <span style="font-size:2.4rem">🛡️</span>
          <div>
            <h1 style="margin:0;font-size:1.9rem;font-weight:800;
                       background:linear-gradient(90deg,#58a6ff,#79c0ff);
                       -webkit-background-clip:text;-webkit-text-fill-color:transparent">
              SentinelAI
            </h1>
            <p style="margin:0;color:#8b949e;font-size:0.9rem">
              Autonomous Cybersecurity Incident Triage &amp; Remediation • Powered by Gemini
            </p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    # Metrics strip (auto-refreshes on re-run)
    render_metrics()

    st.divider()

    # Main tabs
    tabs = st.tabs(
        [
            "📥 Incident Input",
            "🧠 AI Reasoning",
            "🔧 Remediation Console",
            "📜 Incident History",
        ]
    )

    with tabs[0]:
        render_input_tab(api_key, model_name)

    with tabs[1]:
        render_reasoning_tab()

    with tabs[2]:
        render_remediation_tab()

    with tabs[3]:
        render_history_tab()


if __name__ == "__main__":
    main()
