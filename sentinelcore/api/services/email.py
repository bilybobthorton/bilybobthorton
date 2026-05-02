from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"

# Threat level → display colour (used in HTML email)
_LEVEL_COLOR = {
    "malicious": "#ef4444",   # red-500
    "suspicious": "#f97316",  # orange-500
    "clean": "#22c55e",       # green-500
}


def _build_html(
    filename: str,
    scan_id: str,
    threat_level: str,
    confidence: float,
    indicators: list[str],
    scan_url: str,
) -> str:
    color = _LEVEL_COLOR.get(threat_level, "#94a3b8")
    level_label = threat_level.upper()
    indicator_rows = "".join(
        f'<li style="margin:4px 0;color:#94a3b8;font-size:13px;">{ind}</li>'
        for ind in indicators[:10]
    )
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 20px;">
      <table width="560" cellpadding="0" cellspacing="0"
             style="background:#0d0d14;border:1px solid #1e293b;border-radius:12px;overflow:hidden;">

        <!-- Header -->
        <tr><td style="background:#0d0d14;padding:24px 32px;border-bottom:1px solid #1e293b;">
          <table cellpadding="0" cellspacing="0">
            <tr>
              <td style="width:28px;height:28px;background:#dc2626;border-radius:6px;text-align:center;vertical-align:middle;">
                <span style="color:#fff;font-weight:700;font-size:11px;">SC</span>
              </td>
              <td style="padding-left:10px;color:#fff;font-weight:600;font-size:15px;">SentinelCore</td>
            </tr>
          </table>
        </td></tr>

        <!-- Threat banner -->
        <tr><td style="padding:0;">
          <div style="background:{color}18;border-bottom:1px solid {color}40;padding:20px 32px;">
            <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:.08em;color:{color};text-transform:uppercase;">
              Scan complete — threat detected
            </p>
            <p style="margin:8px 0 0;font-size:28px;font-weight:800;color:#fff;">{level_label}</p>
          </div>
        </td></tr>

        <!-- Body -->
        <tr><td style="padding:28px 32px;">
          <table width="100%" cellpadding="0" cellspacing="0">

            <!-- File info -->
            <tr><td style="padding-bottom:20px;">
              <p style="margin:0;font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;">File analyzed</p>
              <p style="margin:4px 0 0;font-size:15px;color:#e2e8f0;font-weight:500;word-break:break-all;">{filename}</p>
            </td></tr>

            <!-- Confidence -->
            <tr><td style="padding-bottom:20px;">
              <p style="margin:0;font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;">Confidence</p>
              <p style="margin:4px 0 0;font-size:15px;color:#e2e8f0;font-weight:500;">{confidence:.0%}</p>
            </td></tr>

            <!-- Indicators -->
            {"<tr><td style='padding-bottom:24px;'><p style='margin:0 0 8px;font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;'>Key indicators</p><ul style='margin:0;padding-left:18px;'>" + indicator_rows + "</ul></td></tr>" if indicators else ""}

            <!-- CTA -->
            <tr><td style="padding-top:8px;">
              <a href="{scan_url}"
                 style="display:inline-block;background:#dc2626;color:#fff;text-decoration:none;
                        font-weight:600;font-size:14px;padding:12px 24px;border-radius:8px;">
                View full scan report →
              </a>
            </td></tr>

          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="padding:20px 32px;border-top:1px solid #1e293b;">
          <p style="margin:0;font-size:12px;color:#475569;">
            You received this because you have scan notifications enabled.
            Scan ID: <span style="font-family:monospace;color:#64748b;">{scan_id[:16]}…</span>
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _build_text(
    filename: str,
    scan_id: str,
    threat_level: str,
    confidence: float,
    indicators: list[str],
    scan_url: str,
) -> str:
    lines = [
        "SentinelCore — Scan Alert",
        "=" * 40,
        f"Result    : {threat_level.upper()}",
        f"File      : {filename}",
        f"Confidence: {confidence:.0%}",
        f"Scan ID   : {scan_id}",
        "",
    ]
    if indicators:
        lines.append("Key indicators:")
        for ind in indicators[:10]:
            lines.append(f"  • {ind}")
        lines.append("")
    lines += [f"Full report: {scan_url}", "", "— SentinelCore"]
    return "\n".join(lines)


async def send_verification_email(
    *,
    to_email: str,
    token: str,
    base_url: str,
    api_key: str,
    from_email: str,
) -> bool:
    if not api_key:
        return False

    verify_url = f"{base_url.rstrip('/')}/verify-email?token={token}"
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 20px;">
      <table width="520" cellpadding="0" cellspacing="0"
             style="background:#0d0d14;border:1px solid #1e293b;border-radius:12px;overflow:hidden;">
        <tr><td style="padding:24px 32px;border-bottom:1px solid #1e293b;">
          <table cellpadding="0" cellspacing="0"><tr>
            <td style="width:28px;height:28px;background:#dc2626;border-radius:6px;text-align:center;vertical-align:middle;">
              <span style="color:#fff;font-weight:700;font-size:11px;">SC</span>
            </td>
            <td style="padding-left:10px;color:#fff;font-weight:600;font-size:15px;">SentinelCore</td>
          </tr></table>
        </td></tr>
        <tr><td style="padding:32px;">
          <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#fff;">Verify your email</p>
          <p style="margin:0 0 24px;font-size:14px;color:#94a3b8;line-height:1.6;">
            Click the button below to verify your email address and activate your SentinelCore account.
            This link expires in 24 hours.
          </p>
          <a href="{verify_url}"
             style="display:inline-block;background:#dc2626;color:#fff;text-decoration:none;
                    font-weight:600;font-size:14px;padding:12px 28px;border-radius:8px;">
            Verify email address →
          </a>
          <p style="margin:24px 0 0;font-size:12px;color:#475569;">
            Or paste this link: <span style="color:#64748b;font-family:monospace;word-break:break-all;">{verify_url}</span>
          </p>
        </td></tr>
        <tr><td style="padding:20px 32px;border-top:1px solid #1e293b;">
          <p style="margin:0;font-size:12px;color:#475569;">If you didn't create a SentinelCore account, you can safely ignore this email.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    payload = {
        "from": from_email,
        "to": [to_email],
        "subject": "Verify your SentinelCore email",
        "html": html,
        "text": f"SentinelCore — Verify your email\n\nClick here: {verify_url}\n\nIf you didn't sign up, ignore this email.",
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                RESEND_API_URL,
                json=payload,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            )
            r.raise_for_status()
            logger.info("Verification email sent to %s", to_email)
            return True
    except Exception as exc:
        logger.warning("Failed to send verification email: %s", exc)
        return False


async def send_scan_alert(
    *,
    to_email: str,
    filename: str,
    scan_id: str,
    threat_level: str,
    confidence: float,
    indicators: list[str],
    base_url: str,
    api_key: str,
    from_email: str,
) -> bool:
    """Send a threat alert email via Resend. Returns True on success."""
    if not api_key or threat_level not in ("malicious", "suspicious"):
        return False

    scan_url = f"{base_url.rstrip('/')}/scan/{scan_id}"
    subject_prefix = "🚨 Malware detected" if threat_level == "malicious" else "⚠️ Suspicious file"
    subject = f"{subject_prefix}: {filename}"

    payload = {
        "from": from_email,
        "to": [to_email],
        "subject": subject,
        "html": _build_html(filename, scan_id, threat_level, confidence, indicators, scan_url),
        "text": _build_text(filename, scan_id, threat_level, confidence, indicators, scan_url),
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                RESEND_API_URL,
                json=payload,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            )
            r.raise_for_status()
            logger.info("Scan alert email sent to %s for scan %s", to_email, scan_id)
            return True
    except Exception as exc:
        logger.warning("Failed to send scan alert email: %s", exc)
        return False
