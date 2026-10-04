"""Render JWT analysis results as a self-contained HTML report."""
import html
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import AnalysisResult


SEV_COLORS = {
    "critical": "#ef4444",
    "high": "#f59e0b",
    "medium": "#3b82f6",
    "low": "#64748b",
    "info": "#8b9bb4",
}


def _sev_badge(sev: str) -> str:
    color = SEV_COLORS.get(sev, "#8b9bb4")
    return (
        f'<span style="background:{color}22;color:{color};'
        f'border:1px solid {color}55;padding:3px 9px;border-radius:5px;'
        f'font-size:10.5px;font-weight:700;letter-spacing:.5px">'
        f'{sev.upper()}</span>'
    )


def render_html(result: AnalysisResult, title: str = "JWT Analysis Report") -> str:
    """Return a complete, self-contained HTML report string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Gauge geometry
    score = result.score
    color = ("#10b981" if score >= 80
             else "#06b6d4" if score >= 60
             else "#f59e0b" if score >= 40
             else "#ef4444")
    circumference = 439.8
    offset = circumference - (circumference * score / 100)

    findings_html = ""
    if not result.findings:
        findings_html = (
            '<div style="background:#10b98111;border:1px solid #10b98144;'
            'border-radius:12px;padding:24px;text-align:center;color:#34d399">'
            '✅ No issues found. This token looks clean.</div>'
        )
    else:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ordered = sorted(result.findings, key=lambda f: order.get(f.severity, 9))
        for f in ordered:
            evidence = ""
            if f.evidence:
                evidence = (
                    f'<div style="background:#070b14;border:1px solid #1f2b45;'
                    f'border-radius:8px;padding:10px 14px;font-family:monospace;'
                    f'font-size:12.5px;color:#a5f3d0;margin-top:10px;'
                    f'word-break:break-all">{html.escape(f.evidence)}</div>'
                )
            findings_html += f"""
            <div style="background:#0f1626;border:1px solid #1f2b45;
                        border-left:3px solid {SEV_COLORS.get(f.severity,'#64748b')};
                        border-radius:12px;padding:20px 22px;margin-bottom:12px">
              <div style="margin-bottom:8px">{_sev_badge(f.severity)}
                <span style="color:#8b9bb4;font-size:11.5px;margin-left:8px">{f.id}</span>
              </div>
              <h3 style="font-size:14.5px;font-weight:600;margin-bottom:6px">{html.escape(f.title)}</h3>
              <p style="font-size:13.5px;color:#8b9bb4;margin-bottom:10px">{html.escape(f.description)}</p>
              <div style="background:#070b14;border:1px solid #1f2b45;border-radius:8px;
                          padding:10px 14px;font-size:13px">
                <strong style="color:#10b981">Fix:</strong> {html.escape(f.remediation)}
              </div>
              {evidence}
            </div>
            """

    header_json = html.escape(json.dumps_safe(result.header)) if False else html.escape(str(result.header))
    payload_json = html.escape(str(result.payload))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{html.escape(title)}</title>
<style>
  body{{font-family:'Inter',system-ui,sans-serif;background:#070b14;color:#e6edf7;
       margin:0;padding:40px 20px;line-height:1.6}}
  .wrap{{max-width:900px;margin:0 auto}}
  h1{{font-size:28px;letter-spacing:-.8px;margin-bottom:6px}}
  .sub{{color:#8b9bb4;font-size:13.5px;margin-bottom:28px}}
  .head{{display:flex;gap:34px;align-items:center;background:linear-gradient(160deg,#0f1626,#0a0f1c);
        border:1px solid #1f2b45;border-radius:18px;padding:30px;margin-bottom:26px}}
  .gauge{{position:relative;width:150px;height:150px;flex:0 0 auto}}
  .gauge svg{{transform:rotate(-90deg)}}
  .gauge .num{{position:absolute;inset:0;display:grid;place-items:center;
              font-size:38px;font-weight:800;color:{color}}}
  .gauge .lbl{{position:absolute;bottom:28px;width:100%;text-align:center;
              font-size:11px;color:#8b9bb4;text-transform:uppercase;letter-spacing:.5px}}
  .meta h2{{font-size:19px;margin-bottom:4px}}
  .meta p{{color:#8b9bb4;font-size:13px}}
  pre{{background:#070b14;border:1px solid #1f2b45;border-radius:10px;
      padding:14px 16px;font-size:12.5px;color:#a5f3d0;overflow-x:auto;
      line-height:1.5;margin:10px 0 22px}}
  .section{{font-size:17px;font-weight:700;margin:28px 0 12px}}
  footer{{margin-top:36px;padding-top:20px;border-top:1px solid #1f2b45;
         text-align:center;color:#8b9bb4;font-size:12.5px}}
</style>
</head>
<body>
  <div class="wrap">
    <h1>🔐 JWT Security Report</h1>
    <div class="sub">Generated {now} · {len(result.findings)} finding(s)</div>

    <div class="head">
      <div class="gauge">
        <svg width="150" height="150" viewBox="0 0 150 150">
          <circle cx="75" cy="75" r="70" fill="none" stroke="#1f2b45" stroke-width="11"/>
          <circle cx="75" cy="75" r="70" fill="none" stroke="{color}" stroke-width="11"
                  stroke-linecap="round" stroke-dasharray="{circumference}"
                  stroke-dashoffset="{offset}"/>
        </svg>
        <div class="num">{score}</div>
        <div class="lbl">/ 100</div>
      </div>
      <div class="meta">
        <h2>Algorithm: {html.escape(result.algorithm)}</h2>
        <p>Score {score}/100 · {len(result.findings)} issue(s) found</p>
      </div>
    </div>

    <div class="section">Header</div>
    <pre>{header_json}</pre>

    <div class="section">Payload</div>
    <pre>{payload_json}</pre>

    <div class="section">Findings &amp; Fixes</div>
    {findings_html}

    <footer>
      SecurAI JWT Analyzer · <a href="https://github.com/ElhamBidarigh/jwt-analyzer"
      style="color:#10b981">GitHub</a> · Use only on systems you own.
    </footer>
  </div>
</body>
</html>
"""


def save_html(result: AnalysisResult, path: str | Path) -> Path:
    out = Path(path)
    out.write_text(render_html(result), encoding="utf-8")
    return out
