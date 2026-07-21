"""SMTP email delivery for invitations and operator diagnostics."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from functools import lru_cache
from html import escape

from app.config import BackendSettings, get_settings

logger = logging.getLogger(__name__)
DEFAULT_EMAIL_FROM = "SentryStrike <no-reply@sentrystrike.local>"

BRAND_BLUE = "#2864D7"
BRAND_BLUE_DARK = "#1747AD"
BRAND_BLUE_SOFT = "#E7EEFC"
PAGE_BACKGROUND = "#F7F9FC"
PAPER = "#FCFDFF"
INK = "#151B26"
SUBTLE_INK = "#4C5667"
MUTED_INK = "#717B8C"
HAIRLINE = "#D6DDEA"


def render_workspace_invite_email(
    *,
    org_name: str | None,
    role: str,
    link: str | None,
    token: str,
    owns_workspace: bool = False,
) -> tuple[str, str, str]:
    """Return a branded invitation as subject, plain text, and email-safe HTML."""
    workspace = org_name or "your team's"
    role_label = "Workspace owner" if owns_workspace else role.replace("_", " ").title()
    if owns_workspace:
        subject = f"You're invited to set up the {workspace} workspace on SentryStrike"
        headline = f"Set up the {workspace} workspace"
        introduction = (
            f"You've been invited to create and own the '{workspace}' workspace on "
            "SentryStrike."
        )
        action_label = "Set up workspace"
    else:
        subject = (
            f"You're invited to join the {org_name} workspace on SentryStrike"
            if org_name
            else "You're invited to join a workspace on SentryStrike"
        )
        headline = f"Join {workspace} on SentryStrike"
        introduction = (
            f"You've been invited to join the {workspace} workspace on SentryStrike "
            f"as a {role}."
        )
        action_label = "Accept invitation"

    destination = link or (
        "your SentryStrike signup page with this invite token:\n\n"
        f"    {token}"
    )
    body_text = (
        "Hello,\n\n"
        f"{introduction}\n\n"
        f"To accept, complete registration here:\n\n    {destination}\n\n"
        "This invitation is single-use and will expire automatically. If you weren't "
        "expecting it, you can safely ignore this email.\n"
    )

    safe_workspace = escape(workspace)
    safe_role = escape(role_label)
    safe_headline = escape(headline)
    safe_introduction = escape(introduction)
    safe_action_label = escape(action_label)
    if link:
        safe_link = escape(link, quote=True)
        action_html = f"""
          <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: 30px 0 26px;">
            <tr>
              <td bgcolor="{BRAND_BLUE}" style="border-radius: 8px;">
                <a href="{safe_link}" style="display: inline-block; padding: 14px 22px; border: 1px solid {BRAND_BLUE}; border-radius: 8px; color: #FFFFFF; font-family: 'Segoe UI', sans-serif; font-size: 15px; font-weight: 700; line-height: 20px; text-decoration: none;">{safe_action_label}&nbsp;&nbsp;&rarr;</a>
              </td>
            </tr>
          </table>
          <p style="margin: 0 0 8px; color: {MUTED_INK}; font-family: 'Segoe UI', sans-serif; font-size: 12px; line-height: 18px;">Button not working? Copy and paste this address into your browser:</p>
          <p style="margin: 0; overflow-wrap: anywhere; word-break: break-word; font-family: Consolas, 'Courier New', monospace; font-size: 11px; line-height: 18px;"><a href="{safe_link}" style="color: {BRAND_BLUE_DARK}; text-decoration: underline;">{safe_link}</a></p>
        """
    else:
        safe_token = escape(token)
        action_html = f"""
          <p style="margin: 28px 0 10px; color: {SUBTLE_INK}; font-family: 'Segoe UI', sans-serif; font-size: 13px; line-height: 20px;">Open the SentryStrike registration page and enter this invite token:</p>
          <div style="padding: 14px 16px; border: 1px solid {HAIRLINE}; border-radius: 8px; background: {PAGE_BACKGROUND}; overflow-wrap: anywhere; word-break: break-word; color: {INK}; font-family: Consolas, 'Courier New', monospace; font-size: 12px; line-height: 20px;">{safe_token}</div>
        """

    body_html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light only">
    <title>{escape(subject)}</title>
  </head>
  <body style="margin: 0; padding: 0; background: {PAGE_BACKGROUND}; color: {INK};">
    <div style="display: none; max-height: 0; overflow: hidden; opacity: 0;">Your SentryStrike workspace invitation is ready.</div>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="{PAGE_BACKGROUND}" style="width: 100%; background: {PAGE_BACKGROUND};">
      <tr>
        <td align="center" style="padding: 40px 16px;">
          <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" bgcolor="{PAPER}" style="width: 100%; max-width: 600px; background: {PAPER}; border: 1px solid {HAIRLINE}; border-radius: 12px; overflow: hidden;">
            <tr><td bgcolor="{BRAND_BLUE}" style="height: 5px; font-size: 0; line-height: 0;">&nbsp;</td></tr>
            <tr>
              <td style="padding: 26px 34px 24px; border-bottom: 1px solid {HAIRLINE};">
                <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                  <tr>
                    <td width="34" height="34" align="center" valign="middle" bgcolor="{BRAND_BLUE}" style="width: 34px; height: 34px; border-radius: 9px; color: #FFFFFF; font-family: 'Segoe UI', sans-serif; font-size: 16px; font-weight: 800;">S</td>
                    <td style="padding-left: 11px; color: {INK}; font-family: 'Segoe UI', sans-serif; font-size: 17px; font-weight: 750; letter-spacing: -0.2px;">SentryStrike</td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding: 38px 34px 34px;">
                <span style="display: inline-block; padding: 5px 9px; border-radius: 999px; background: {BRAND_BLUE_SOFT}; color: {BRAND_BLUE_DARK}; font-family: 'Segoe UI', sans-serif; font-size: 10px; font-weight: 800; letter-spacing: 1.2px; line-height: 14px; text-transform: uppercase;">Workspace invitation</span>
                <h1 style="margin: 18px 0 14px; color: {INK}; font-family: 'Segoe UI', sans-serif; font-size: 30px; font-weight: 750; letter-spacing: -0.8px; line-height: 38px;">{safe_headline}</h1>
                <p style="margin: 0; color: {SUBTLE_INK}; font-family: 'Segoe UI', sans-serif; font-size: 15px; line-height: 24px;">{safe_introduction}</p>
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin-top: 26px; border-top: 1px solid {HAIRLINE}; border-bottom: 1px solid {HAIRLINE};">
                  <tr>
                    <td style="padding: 13px 0; color: {MUTED_INK}; font-family: 'Segoe UI', sans-serif; font-size: 12px; line-height: 18px;">Workspace</td>
                    <td align="right" style="padding: 13px 0; color: {INK}; font-family: 'Segoe UI', sans-serif; font-size: 13px; font-weight: 700; line-height: 18px;">{safe_workspace}</td>
                  </tr>
                  <tr>
                    <td style="padding: 13px 0; border-top: 1px solid {HAIRLINE}; color: {MUTED_INK}; font-family: 'Segoe UI', sans-serif; font-size: 12px; line-height: 18px;">Access</td>
                    <td align="right" style="padding: 13px 0; border-top: 1px solid {HAIRLINE}; color: {INK}; font-family: 'Segoe UI', sans-serif; font-size: 13px; font-weight: 700; line-height: 18px;">{safe_role}</td>
                  </tr>
                </table>
                {action_html}
                <div style="margin-top: 28px; padding: 15px 16px; border-left: 3px solid {BRAND_BLUE}; background: {BRAND_BLUE_SOFT}; color: {SUBTLE_INK}; font-family: 'Segoe UI', sans-serif; font-size: 12px; line-height: 19px;"><strong style="color: {INK};">Security note:</strong> This invitation is single-use and expires automatically. SentryStrike will never ask you to share this link or your password.</div>
              </td>
            </tr>
            <tr>
              <td style="padding: 21px 34px; border-top: 1px solid {HAIRLINE}; background: {PAGE_BACKGROUND}; color: {MUTED_INK}; font-family: 'Segoe UI', sans-serif; font-size: 11px; line-height: 17px;">You received this email because someone invited you to a SentryStrike workspace. If you were not expecting it, no action is required.</td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"""
    return subject, body_text, body_html


class SmtpEmailBackend:
    """Send over SMTP with optional STARTTLS and authentication."""

    name = "smtp"

    def __init__(self, settings: BackendSettings) -> None:
        self._settings = settings
        self.from_address = settings.email_from
        if self.from_address == DEFAULT_EMAIL_FROM and settings.email_smtp_user:
            self.from_address = settings.email_smtp_user

    def send(
        self, *, to: str, subject: str, body_text: str, body_html: str | None = None
    ) -> None:
        settings = self._settings
        message = EmailMessage()
        message["From"] = self.from_address
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body_text)
        if body_html:
            message.add_alternative(body_html, subtype="html")

        with smtplib.SMTP(settings.email_smtp_host, settings.email_smtp_port, timeout=30) as client:
            client.ehlo()
            if settings.email_smtp_starttls:
                client.starttls()
                client.ehlo()
            if settings.email_smtp_user and settings.email_smtp_password:
                client.login(
                    settings.email_smtp_user,
                    settings.email_smtp_password.get_secret_value(),
                )
            refused = client.send_message(message)
            if refused:
                raise smtplib.SMTPRecipientsRefused(refused)
        logger.info("SMTP server accepted email to %s (subject=%s)", to, subject)


@lru_cache
def get_email_backend() -> SmtpEmailBackend:
    """Return the configured SMTP backend (cached singleton)."""
    return SmtpEmailBackend(get_settings())
