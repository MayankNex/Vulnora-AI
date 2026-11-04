import json
import os

import streamlit as st
from dotenv import load_dotenv

from vulnora.scanner import ScanError, scan_website
from vulnora.explain import explain_findings
from vulnora.scoring import calculate_score
from vulnora.remediation import get_fix_preview

load_dotenv()
st.set_page_config(page_title="Vulnora AI", page_icon="🛡️", layout="wide")
st.title("🛡️ Vulnora AI")
st.caption("A clear, defensive security baseline check for websites you own.")

with st.sidebar:
    st.header("Scan controls")
    st.warning("Only scan websites you own or have explicit permission to assess.")
    st.write("Passive checks only: no exploitation, brute-force, crawling, or automatic changes.")
    st.markdown("[Project on GitHub](https://github.com/MayankNex/Vulnora-AI)")
    st.markdown("[Security scope & limitations](https://github.com/MayankNex/Vulnora-AI/blob/main/docs/SECURITY_AND_LIMITATIONS.md)")

url = st.text_input("Website URL", placeholder="https://your-domain.com")
authorized = st.checkbox("I own this website or have explicit permission to assess it.")
if st.button("🔎 Run safe scan", type="primary", disabled=not authorized or not url.strip()):
    with st.spinner("Reviewing the public landing-page response..."):
        try:
            st.session_state["vulnora_report"] = scan_website(url.strip())
            st.session_state.pop("vulnora_ai", None)
        except ScanError as exc:
            st.error(str(exc))
        except Exception:
            st.error("Scan failed. Check the URL, DNS, network connection, and try again.")

report = st.session_state.get("vulnora_report")
if report:
    findings = report.get("findings", [])
    score = calculate_score(findings)
    st.divider()
    st.subheader("Security baseline")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Baseline score", f"{score['score']}/100", score["label"])
    c2.metric("Total findings", len(findings))
    c3.metric("High", sum(x["severity"] == "High" for x in findings))
    c4.metric("Medium", sum(x["severity"] == "Medium" for x in findings))
    st.progress(score["score"] / 100)
    st.caption(score["note"])

    with st.expander("Target and scan metadata", expanded=True):
        st.write(f"**Requested URL:** {report['requested_url']}")
        st.write(f"**Final URL:** {report['final_url']}")
        st.write(f"**HTTP status:** {report['status_code']}")
        st.write(f"**HTTPS:** {'Yes' if report['https'] else 'No'}")

    tab_findings, tab_fixes, tab_ai, tab_export = st.tabs(
        ["Findings", "Fix guidance", "AI explanation", "Export"]
    )
    with tab_findings:
        if not findings:
            st.success("No checked baseline issues were observed. This does not prove the website is secure.")
        else:
            severity_filter = st.multiselect(
                "Filter by severity", ["High", "Medium", "Low"],
                default=["High", "Medium", "Low"]
            )
            visible = [f for f in findings if f["severity"] in severity_filter]
            for item in visible:
                with st.expander(f"{item['severity']} · {item['title']}", expanded=item["severity"] == "High"):
                    st.write(item["description"])
                    st.markdown(f"**Observed evidence:** {item['evidence']}")
                    st.markdown(f"**Recommended action:** {item['remediation']}")
    with tab_fixes:
        st.info("These are examples for manual review. Vulnora never edits your server or deploys changes.")
        platform = st.selectbox("Choose your platform", ["Nginx", "Apache", "Cloudflare", "WordPress"])
        st.code(get_fix_preview(platform), language="nginx" if platform == "Nginx" else "apache" if platform == "Apache" else "text")
        st.warning("Back up first. Test in staging. A Content Security Policy can break legitimate scripts, styles, or embeds if copied without customization.")
    with tab_ai:
        if not os.getenv("OPENAI_API_KEY"):
            st.info("AI is optional. Add OPENAI_API_KEY to a local .env file to enable explanations. Core scanning works without it.")
        elif st.button("✨ Explain findings with AI"):
            with st.spinner("Preparing a plain-language explanation..."):
                try:
                    st.session_state["vulnora_ai"] = explain_findings(report)
                except Exception:
                    st.warning("AI explanation is unavailable. Use the evidence and guidance in the Findings tab.")
        if st.session_state.get("vulnora_ai"):
            st.write(st.session_state["vulnora_ai"])
    with tab_export:
        st.download_button(
            "⬇️ Download JSON report",
            data=json.dumps({"report": report, "score": score}, indent=2),
            file_name="vulnora-report.json",
            mime="application/json",
        )
        st.json({"score": score, "findings": findings, "limitations": report.get("limitations", [])})

    st.caption("A missing header is a configuration observation, not a confirmed exploitable vulnerability.")
else:
    st.markdown("### What it checks")
    st.markdown("- HTTPS usage and common response security headers\n- Basic cookie security attributes\n- Risk-prioritized findings and manual fix examples\n- Optional AI explanations and JSON export")
