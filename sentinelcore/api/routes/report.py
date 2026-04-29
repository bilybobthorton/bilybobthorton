"""
Scan report generation — Pro+ feature.
Returns a structured JSON report or a rendered HTML report
that the browser can print-to-PDF.
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user
from api.database import get_db
from api.models.scan import ScanJob, User

router = APIRouter(prefix="/api/v1/report", tags=["report"])


def _require_pro(user: User = Depends(get_current_user)) -> User:
    if user.tier not in ("pro", "enterprise"):
        raise HTTPException(
            status_code=403,
            detail="Full scan reports require a Pro or Enterprise plan",
        )
    return user


@router.get("/{scan_id}/json")
async def report_json(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(_require_pro),
):
    """Full structured JSON report for a completed scan."""
    job = await _get_job(scan_id, db)
    return _build_report_dict(job, current_user)


@router.get("/{scan_id}", response_class=HTMLResponse)
async def report_html(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(_require_pro),
):
    """
    Rendered HTML report — open in browser and use File → Print → Save as PDF.
    Styled for clean A4/Letter output.
    """
    job = await _get_job(scan_id, db)
    report = _build_report_dict(job, current_user)
    return HTMLResponse(content=_render_html(report))


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _get_job(scan_id: str, db: AsyncSession) -> ScanJob:
    try:
        uid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    result = await db.execute(select(ScanJob).where(ScanJob.id == uid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job.status != "complete":
        raise HTTPException(status_code=409, detail=f"Scan is not complete (status: {job.status})")
    return job


def _build_report_dict(job: ScanJob, user: User) -> dict:
    rj = job.result_json or {}
    hashes = rj.get("hashes", {})
    pe = rj.get("pe_info") or {}
    sections = pe.get("sections", [])
    imports = pe.get("imports", {})

    return {
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": str(job.id),
        "analyst": user.email,
        "file": {
            "name": job.filename,
            "size_bytes": job.file_size,
            "type": rj.get("file_type", "unknown"),
            "mime_type": rj.get("mime_type", ""),
        },
        "verdict": {
            "threat_level": job.threat_level,
            "confidence": job.confidence,
            "indicators": rj.get("indicators", []),
        },
        "hashes": {
            "md5": hashes.get("md5"),
            "sha1": hashes.get("sha1"),
            "sha256": hashes.get("sha256"),
            "ssdeep": hashes.get("ssdeep"),
        },
        "pe_analysis": {
            "is_pe": pe.get("is_pe", False),
            "is_64bit": pe.get("is_64bit", False),
            "is_packed": pe.get("is_packed", False),
            "is_signed": pe.get("is_signed", False),
            "is_dotnet": pe.get("is_dotnet", False),
            "has_overlay": pe.get("has_overlay", False),
            "overlay_size": pe.get("overlay_size", 0),
            "entry_point": pe.get("entry_point"),
            "sections": sections,
            "import_dll_count": len(imports),
            "imports": {dll: funcs[:20] for dll, funcs in list(imports.items())[:15]},
            "exports": pe.get("exports", [])[:50],
        },
        "strings": rj.get("strings") or {},
        "yara_matches": rj.get("yara_matches", []),
        "intelligence": {
            "ml": rj.get("ml"),
            "virustotal": rj.get("virustotal"),
            "otx": rj.get("otx"),
        },
        "scan_completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


def _render_html(r: dict) -> str:
    verdict = r["verdict"]
    f = r["file"]
    hashes = r["hashes"]
    pe = r["pe_analysis"]
    intel = r["intelligence"]
    vt = intel.get("virustotal") or {}
    otx = intel.get("otx") or {}
    ml = intel.get("ml") or {}

    threat_color = {
        "malicious": "#ef4444",
        "suspicious": "#f59e0b",
        "clean": "#22c55e",
    }.get(verdict["threat_level"] or "unknown", "#94a3b8")

    indicators_html = "".join(
        f'<li style="margin:4px 0;color:#e2e8f0;">⚠ {ind}</li>'
        for ind in verdict["indicators"]
    ) or '<li style="color:#94a3b8;">No indicators detected</li>'

    sections_html = "".join(
        f"""<tr>
              <td>{s.get("name","")}</td>
              <td>{s.get("entropy",0):.2f}</td>
              <td>{", ".join(s.get("flags",[]))}</td>
              <td>{s.get("raw_size",0):,}</td>
            </tr>"""
        for s in pe.get("sections", [])
    )

    yara_html = "".join(
        f'<li style="margin:3px 0;color:#e2e8f0;">✓ {m.get("rule_name","")}'
        f'<span style="color:#94a3b8;font-size:11px;margin-left:8px;">'
        f'{m.get("meta",{}).get("description","")}</span></li>'
        for m in r.get("yara_matches", [])
    ) or '<li style="color:#94a3b8;">No YARA matches</li>'

    intel_rows = ""
    if ml:
        status = "MALICIOUS" if ml.get("malicious") else "CLEAN"
        intel_rows += f'<tr><td>ML Score</td><td>{ml.get("score",0)*100:.1f}% ({status})</td></tr>'
    if vt.get("found"):
        intel_rows += f'<tr><td>VirusTotal</td><td>{vt.get("malicious",0)}/{vt.get("total_engines",0)} engines · {vt.get("popular_threat_name","")}</td></tr>'
    if otx.get("found"):
        families = ", ".join(otx.get("malware_families", [])) or "—"
        intel_rows += f'<tr><td>OTX</td><td>{otx.get("pulse_count",0)} pulse(s) · {families}</td></tr>'
    if not intel_rows:
        intel_rows = '<tr><td colspan="2" style="color:#94a3b8;">No threat intelligence hits</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelCore Report — {f["name"]}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Inter', sans-serif; background: #0a0a0f; color: #e2e8f0; font-size: 13px; line-height: 1.6; }}
  .page {{ max-width: 860px; margin: 0 auto; padding: 40px 48px; }}
  header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 32px; border-bottom: 1px solid #1e293b; padding-bottom: 24px; }}
  .logo {{ display: flex; align-items: center; gap: 10px; }}
  .logo-box {{ width: 32px; height: 32px; background: #dc2626; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 12px; color: white; }}
  .logo-name {{ font-weight: 700; font-size: 18px; color: white; }}
  .meta {{ font-size: 11px; color: #64748b; text-align: right; }}
  .verdict-box {{ border: 1px solid; border-radius: 12px; padding: 20px 24px; margin-bottom: 28px; display: flex; align-items: center; justify-content: space-between; border-color: {threat_color}33; background: {threat_color}11; }}
  .verdict-label {{ font-size: 24px; font-weight: 700; color: {threat_color}; text-transform: uppercase; }}
  .confidence {{ font-size: 13px; color: #94a3b8; }}
  .confidence span {{ font-size: 28px; font-weight: 700; color: white; }}
  section {{ margin-bottom: 28px; }}
  h2 {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; color: #64748b; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-bottom: 14px; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
  .field {{ background: #0f172a; border-radius: 8px; padding: 10px 14px; }}
  .field-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; margin-bottom: 3px; }}
  .field-value {{ font-size: 13px; color: #e2e8f0; font-family: 'JetBrains Mono', monospace; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ text-align: left; color: #64748b; font-weight: 600; font-size: 11px; padding: 6px 10px; border-bottom: 1px solid #1e293b; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid #0f172a; color: #e2e8f0; }}
  tr:hover td {{ background: #0f172a; }}
  ul {{ list-style: none; padding: 0; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge-mal {{ background: #7f1d1d; color: #fca5a5; }}
  .badge-sus {{ background: #78350f; color: #fde68a; }}
  .badge-clean {{ background: #14532d; color: #86efac; }}
  footer {{ margin-top: 40px; border-top: 1px solid #1e293b; padding-top: 16px; font-size: 11px; color: #475569; display: flex; justify-content: space-between; }}
  @media print {{
    body {{ background: white; color: #0f172a; }}
    .page {{ padding: 20px; }}
    .field {{ background: #f8fafc; }}
    td {{ border-bottom: 1px solid #e2e8f0; }}
  }}
</style>
</head>
<body>
<div class="page">
  <header>
    <div class="logo">
      <div class="logo-box">SC</div>
      <div class="logo-name">SentinelCore</div>
    </div>
    <div class="meta">
      <div>Scan Report v{r["report_version"]}</div>
      <div>Generated: {r["generated_at"][:19].replace("T"," ")} UTC</div>
      <div>Analyst: {r["analyst"]}</div>
    </div>
  </header>

  <!-- Verdict -->
  <div class="verdict-box">
    <div>
      <div style="font-size:11px;color:#94a3b8;margin-bottom:4px;">Verdict</div>
      <div class="verdict-label">{verdict["threat_level"] or "unknown"}</div>
    </div>
    <div class="confidence" style="text-align:right;">
      <span>{round((verdict["confidence"] or 0)*100)}%</span><br>confidence
    </div>
  </div>

  <!-- File Info -->
  <section>
    <h2>File Information</h2>
    <div class="grid2">
      <div class="field"><div class="field-label">Filename</div><div class="field-value">{f["name"]}</div></div>
      <div class="field"><div class="field-label">Size</div><div class="field-value">{f["size_bytes"]:,} bytes</div></div>
      <div class="field"><div class="field-label">Type</div><div class="field-value">{f["type"]} / {f["mime_type"]}</div></div>
      <div class="field"><div class="field-label">Scan ID</div><div class="field-value">{r["scan_id"]}</div></div>
    </div>
  </section>

  <!-- Hashes -->
  <section>
    <h2>Cryptographic Hashes</h2>
    <div class="field" style="margin-bottom:8px;"><div class="field-label">MD5</div><div class="field-value">{hashes.get("md5") or "—"}</div></div>
    <div class="field" style="margin-bottom:8px;"><div class="field-label">SHA-256</div><div class="field-value">{hashes.get("sha256") or "—"}</div></div>
    <div class="field"><div class="field-label">ssdeep</div><div class="field-value">{hashes.get("ssdeep") or "—"}</div></div>
  </section>

  <!-- Threat Intelligence -->
  <section>
    <h2>Threat Intelligence</h2>
    <table>
      <tr><th>Source</th><th>Result</th></tr>
      {intel_rows}
    </table>
  </section>

  <!-- Indicators -->
  <section>
    <h2>Indicators of Compromise ({len(verdict["indicators"])})</h2>
    <ul>{indicators_html}</ul>
  </section>

  <!-- YARA -->
  <section>
    <h2>YARA Rule Matches</h2>
    <ul>{yara_html}</ul>
  </section>

  <!-- PE Analysis -->
  {"" if not pe.get("is_pe") else f'''
  <section>
    <h2>PE Analysis</h2>
    <div class="grid2" style="margin-bottom:14px;">
      <div class="field"><div class="field-label">Architecture</div><div class="field-value">{"64-bit" if pe.get("is_64bit") else "32-bit"}</div></div>
      <div class="field"><div class="field-label">Packed</div><div class="field-value">{"Yes ⚠" if pe.get("is_packed") else "No"}</div></div>
      <div class="field"><div class="field-label">Signed</div><div class="field-value">{"Yes ✓" if pe.get("is_signed") else "No"}</div></div>
      <div class="field"><div class="field-label">Overlay</div><div class="field-value">{"Yes — " + str(pe.get("overlay_size",0)) + " bytes" if pe.get("has_overlay") else "None"}</div></div>
    </div>
    <table>
      <tr><th>Section</th><th>Entropy</th><th>Flags</th><th>Raw Size</th></tr>
      {sections_html}
    </table>
  </section>
  '''}

  <footer>
    <span>SentinelCore — Malware Detection Platform</span>
    <span>Scan completed: {r.get("scan_completed_at","")[:19].replace("T"," ") if r.get("scan_completed_at") else "—"} UTC</span>
  </footer>
</div>
</body>
</html>"""
