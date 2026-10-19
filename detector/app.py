"""
app.py — Streamlit dashboard for dns-spoof-detector.

Run with:
    streamlit run app.py
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from detector import analyze

# ── Page config ──────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DNS Spoof Detector",
    page_icon="🛡️",
    layout="wide",
)

# ── Custom CSS for premium look ──────────────────────────────────────────
st.markdown("""
<style>
    /* Overall dark theme tweaks */
    .block-container { padding-top: 2rem; }

    /* Verdict badges */
    .verdict-safe {
        background: linear-gradient(135deg, #00c853, #00e676);
        color: #fff; font-weight: 700; font-size: 1.4rem;
        padding: 0.5rem 1.5rem; border-radius: 0.6rem;
        display: inline-block; text-transform: uppercase;
        box-shadow: 0 4px 14px rgba(0,200,83,0.35);
    }
    .verdict-suspicious {
        background: linear-gradient(135deg, #ff9100, #ffab40);
        color: #fff; font-weight: 700; font-size: 1.4rem;
        padding: 0.5rem 1.5rem; border-radius: 0.6rem;
        display: inline-block; text-transform: uppercase;
        box-shadow: 0 4px 14px rgba(255,145,0,0.35);
    }
    .verdict-spoofed {
        background: linear-gradient(135deg, #d50000, #ff1744);
        color: #fff; font-weight: 700; font-size: 1.4rem;
        padding: 0.5rem 1.5rem; border-radius: 0.6rem;
        display: inline-block; text-transform: uppercase;
        box-shadow: 0 4px 14px rgba(213,0,0,0.35);
    }
    .verdict-unreachable {
        background: linear-gradient(135deg, #616161, #9e9e9e);
        color: #fff; font-weight: 700; font-size: 1.4rem;
        padding: 0.5rem 1.5rem; border-radius: 0.6rem;
        display: inline-block; text-transform: uppercase;
        box-shadow: 0 4px 14px rgba(97,97,97,0.35);
    }

    /* Score gauge container */
    .score-gauge {
        text-align: center; margin: 1rem 0;
    }
    .score-number {
        font-size: 3rem; font-weight: 800; line-height: 1;
    }
    .score-label {
        font-size: 0.85rem; opacity: 0.7; margin-top: 0.25rem;
    }

    /* Reasons list */
    .reason-item {
        padding: 0.4rem 0; border-bottom: 1px solid rgba(255,255,255,0.08);
        font-size: 0.95rem;
    }
</style>
""", unsafe_allow_html=True)

# ── Session state init ───────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []  # list[dict]

# ── Sidebar inputs ──────────────────────────────────────────────────────
st.sidebar.title("🛡️ DNS Spoof Detector")
st.sidebar.markdown("---")

domain_input = st.sidebar.text_input("Domain", value="google.com", help="Single domain to scan")
suspect_host = st.sidebar.text_input("Suspect Resolver IP", value="8.8.8.8")
suspect_port = st.sidebar.number_input("Suspect Resolver Port", value=53, min_value=1, max_value=65535)

scan_clicked = st.sidebar.button("🔍  Scan", use_container_width=True, type="primary")

st.sidebar.markdown("---")
st.sidebar.subheader("Batch Scan")
batch_text = st.sidebar.text_area(
    "Domains (one per line)",
    placeholder="example.com\ngithub.com\nmicrosoft.com",
    height=120,
)
batch_clicked = st.sidebar.button("🚀  Batch Scan", use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════
# Helper: render a single scan result
# ═══════════════════════════════════════════════════════════════════════════
def _render_result(result: dict) -> None:
    """Display one scan result in the main content area."""

    verdict = result["verdict"]
    score = result["score"]

    # ── Verdict badge + score ────────────────────────────────────────────
    col_v, col_s = st.columns([2, 1])
    with col_v:
        css_class = f"verdict-{verdict.lower()}"
        st.markdown(f'<span class="{css_class}">{verdict}</span>', unsafe_allow_html=True)
        st.caption(f"**Domain:** `{result['domain']}`")
    with col_s:
        # Colour the score number
        if score < 30:
            colour = "#00e676"
        elif score < 60:
            colour = "#ffab40"
        else:
            colour = "#ff1744"
        st.markdown(
            f'<div class="score-gauge">'
            f'<div class="score-number" style="color:{colour}">{score}</div>'
            f'<div class="score-label">Risk Score (0–100)</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── Suspect IPs & TTL ────────────────────────────────────────────────
    c1, c2 = st.columns(2)
    c1.metric("Suspect IPs", ", ".join(result["suspect_ips"]) or "—")
    c2.metric("TTL", f'{result["ttl"]}s' if result["ttl"] is not None else "—")

    # ── Reasons ──────────────────────────────────────────────────────────
    with st.expander("📋  Reasons", expanded=True):
        for r in result["reasons"]:
            st.markdown(f'<div class="reason-item">• {r}</div>', unsafe_allow_html=True)

    # ── Per-check pass/fail ──────────────────────────────────────────────
    with st.expander("✅  Check Results"):
        check_data = []
        for name, status in result.get("checks", {}).items():
            if status == "PASS":
                icon = "✅"
            elif status == "FAIL":
                icon = "❌"
            elif status == "SKIP":
                icon = "⏭️"
            elif status == "NEW":
                icon = "🆕"
            else:
                icon = "ℹ️"
            check_data.append({"Check": name, "Status": f"{icon} {status}"})
        if check_data:
            st.table(pd.DataFrame(check_data))

    # ── Resolver comparison table ────────────────────────────────────────
    table = result.get("resolver_table", [])
    if table:
        with st.expander("🌐  Resolver Comparison", expanded=True):
            df = pd.DataFrame(table)
            df.columns = ["Resolver", "IPs", "TTL", "Match"]
            st.dataframe(df, use_container_width=True, hide_index=True)


# ═══════════════════════════════════════════════════════════════════════════
# Main area
# ═══════════════════════════════════════════════════════════════════════════
st.title("🛡️ DNS Spoof Detector")
st.caption("Analyse DNS responses from a suspect resolver against trusted sources.")

# ── Single scan ──────────────────────────────────────────────────────────
if scan_clicked and domain_input.strip():
    with st.spinner(f"Scanning **{domain_input.strip()}** …"):
        result = analyze(domain_input.strip(), suspect_host, int(suspect_port))
    _render_result(result)
    st.session_state.history.insert(0, result)

# ── Batch scan ───────────────────────────────────────────────────────────
if batch_clicked and batch_text.strip():
    domains = [d.strip() for d in batch_text.strip().splitlines() if d.strip()]
    progress = st.progress(0, text="Starting batch scan…")
    for idx, dom in enumerate(domains):
        progress.progress((idx + 1) / len(domains), text=f"Scanning {dom}…")
        result = analyze(dom, suspect_host, int(suspect_port))
        st.markdown("---")
        _render_result(result)
        st.session_state.history.insert(0, result)
    progress.empty()

# ── Session history ──────────────────────────────────────────────────────
if st.session_state.history:
    st.markdown("---")
    st.subheader("📜 Scan History")
    history_rows = []
    for h in st.session_state.history:
        history_rows.append({
            "Domain": h["domain"],
            "Verdict": h["verdict"],
            "Score": h["score"],
            "IPs": ", ".join(h["suspect_ips"]) if h["suspect_ips"] else "—",
            "Reasons": "; ".join(h["reasons"]),
        })
    st.dataframe(pd.DataFrame(history_rows), use_container_width=True, hide_index=True)
