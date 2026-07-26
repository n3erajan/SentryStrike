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
                    <td width="34" height="34" style="width: 34px; height: 34px;"><img src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjxzdmcgaWQ9IkxheWVyXzEiIGRhdGEtbmFtZT0iTGF5ZXIgMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB2aWV3Qm94PSI0MTYgNDA2IDExNzQgMTE3NCI+DQogIDxkZWZzPg0KICAgIDxzdHlsZT4NCiAgICAgIC5jbHMtMSB7DQogICAgICAgIGZpbGw6ICMwMDc5ZmY7DQogICAgICB9DQogICAgPC9zdHlsZT4NCiAgPC9kZWZzPg0KICA8cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Im02ODUuMzMsMTA1Mi45OWMtNy40NCwyMC4yNC0xNC45Miw0MC40OC0yMi4zMiw2MC43NC02LjczLDE4LjQyLTEzLjI3LDM2LjkyLTIwLjI0LDU1LjI1LS42MSwxLjYtNC4yMSwzLjU1LTUuNzgsMy4xLTU0Ljg5LTE1LjY1LTEwOS43MS0zMS41OC0xNjQuNTQtNDcuNDUtNC40Mi0xLjI4LTguODYtMi40NC0xMy44Ni0zLjgxLDExLjY4LTM0LjIzLDIyLjQyLTY4LjI2LDM1LjA4LTEwMS41Nyw1LjYxLTE0Ljc1LDEuNzktMjguNTEsMS4wMy00Mi42OS0yLjQ5LTQ2LjM4LTUuMzQtOTIuNzQtNy45Mi0xMzkuMTItLjEtMS43My43Ni00LDEuOTYtNS4yNSw0NC43Ny00Ni4yLDk2LjYyLTgyLjI5LDE1NS40Mi0xMDguMzgsNjYuNDUtMjkuNDgsMTM2LTQyLjUsMjA4LjU2LTM4LjQ3LDc4LjQyLDQuMzYsMTUwLjg1LDI3LjM1LDIxNi4wNyw3MS42MSwzLjE0LDIuMTMsNS45Niw3LjMxLDUuOTcsMTEuMDguMzEsOTguMzIuMDksMTk2LjY1LjM2LDI5NC45OC4wNSwxOC45MywxLjc2LDM3Ljg1LDIuNzcsNTguMDctNS43My0xMC41MS0xMi4zMS0xOS45My0xNi4yOS0zMC4zNC0xNy4xNy00NC44OC0yOS42OC05MS4xNC0zOC42LTEzOC4zNS0xLjAyLTUuNC0zLjcxLTcuOTUtOC42MS05LjQ2LTUxLjM3LTE1LjkxLTEwMi42Ni0zMi4wNy0xNTQuMDgtNDcuODMtMzYuNDktMTEuMTktNzMuMTMtMjEuODctMTExLjk2LTMzLjQ0LDEwLjg3LDkuMSwyMC4xMSwxNi44OCwyOS4zOSwyNC42MSwyOS42NywyNC43NCw1OC4zOSw1MC43Nyw4OS40NCw3My42NCwxNC42OSwxMC44MiwzMy42NywxNi4wNCw1MS4wNCwyMi45NSwyMi4yMyw4Ljg1LDQ0Ljg0LDE2LjcyLDY3LjEzLDI1LjQyLDIuMzkuOTMsNS4wMyw0LjQxLDUuMzYsNi45OSw4LjgzLDY3Ljk5LDE2LjQyLDEzNi4xNiwyNi4yMiwyMDQuMDEsOS4zMiw2NC40OSwyMC43OSwxMjguNjgsMzEuNTMsMTkyLjk2LDIuMywxMy43NCw1LjU4LDI3LjMxLDguMzcsNDAuOTcuMTguODkuMDIsMS44NC4wMiwzLjM5LTEyLjc0LTEwLjc5LTI0Ljk5LTIxLjE5LTM3LjI3LTMxLjU1LTc0LjU0LTYyLjkyLTE1MC4yNy0xMjQuMzctMjMxLjkyLTE3Ny45NC0zMy4xOC0yMS43Ny02OC4wMS00MS0xMDEuOS02MS43LTIuNC0xLjQ3LTQuNjgtNS41OS00LjU2LTguMzgsMS42NC0zOS42LDMuNzEtNzkuMTgsNS42NS0xMTguNzYuMDgtMS42Mi4wMS0zLjI0LjAxLTQuODYtLjUxLS4xMy0xLjAzLS4yNi0xLjU0LS4zOVoiLz4NCiAgPHBhdGggY2xhc3M9ImNscy0xIiBkPSJtNDE1LjksODYxLjFjMzMuNjUtNTcuMTUsNzUuNzEtMTA3LjQ3LDEyMi4zMS0xNTUuMzYtNDQuMjIsMTAuMzItODguNDQsMjAuNjUtMTMxLjc2LDMwLjc2LDE2LjAzLTI0Ljc0LDE0Ny4zOC0xMjAuMTMsMjEyLjExLTE1My40OCw3OC45OC00MC42OSwxNjIuMzEtNjguOTEsMjQ5LjE1LTg3LjE1LDg2Ljg5LTE4LjI1LDE3NC43My0yMi40OCwyNjMuNC0xOC4xOC0zOS4wMSw3NC4wOS02Mi4yLDE1My42OC04MC4xNCwyMzQuOTgtNTIuNTUtMjYuODctMTA3LjcyLTQyLjc2LTE2NS44NC00OC45LTc2LjY2LTguMS0xNTEuMSwxLjE2LTIyMy4yNCwyOC4yMS02My4wOCwyMy42NS0xMjAuMDMsNTcuODgtMTcxLjA3LDEwMS43My0yNC45OSwyMS40Ny00OC45Niw0NC4xNC03My4zOSw2Ni4yNi0uNDcuNDItMS4wMi43Ni0xLjUzLDEuMTNaIi8+DQogIDxwYXRoIGNsYXNzPSJjbHMtMSIgZD0ibTE0MjQuNTksOTE5LjE3Yy4yMS0xLjA1LjM3LTEuNTEuMzktMS45OC42LTE2LjEyLjYtMTYuMi0xNS41Mi0xNi4yLTk3LjQ5LS4wMi0xOTQuOTksMC0yOTIuNDgsMC0yLjQ2LDAtNC45MiwwLTcuNjgsMC0uMTEtMS4zNy0uMjYtMi4zMi0uMjYtMy4yNy0uMDItMjUuMTYtLjA5LTUwLjMzLjEzLTc1LjQ5LjAxLTEuNSwyLjQtNC4yOSwzLjY4LTQuMjksMTA2LjQ5LS4zNCwyMTIuOTgtLjUsMzE5LjQ3LS41NCwxNi41OSwwLDIyLjgsNi4xNCwyMi44MiwyMi42Mi4wNyw5Mi44Mi4wMiwxODUuNjQtLjEyLDI3OC40Ni0uMDIsMTQuMTYtNS4zNSwxOS41MS0xOS43NiwxOS41OS00NC4zMy4yNC04OC42Ni4yMy0xMzIuOTkuMjYtNjIuMTYuMDQtMTI0LjMyLS4wMi0xODYuNDkuMTctNS4yMy4wMi03LjQ1LS45Ni02LjkxLTYuNzIuNjgtNy4yNS0yLjMtMTcuMjgsMS40My0yMS4xLDMuNjctMy43NSwxMy43Ni0xLjQzLDIxLjAzLTEuNDQsOTUuNjYtLjA3LDE5MS4zMi0uMTMsMjg2Ljk4LDAsNS40LDAsNi43Ny0xLjY3LDYuNzUtNi43Ny0uMTUtNDkuMzMtLjE4LTk4LjY2LDAtMTQ3Ljk5LjAyLTUuNjctMS42LTcuNC03LjM1LTcuMzktMTAwLjgzLjE1LTIwMS42NS4wNi0zMDIuNDguMTktNC44OCwwLTYuODQtLjkyLTYuMzEtNi4xOS43MS03LjAyLTEuOTItMTYuNTYsMS43NC0yMC40NSwzLjQtMy42MSwxMy4xNy0xLjQ0LDIwLjE0LTEuNDQsOTUuNjYtLjA0LDE5MS4zMi0uMDIsMjg2Ljk4LS4wMiwyLjE2LDAsNC4zMSwwLDYuOCwwWm0tMTE0LjgtNjguNGgtMzQuMjJjMCw4LjQxLS4xNiwxNi4zNy4xNywyNC4zLjA1LDEuMjEsMi4zNCwzLjI4LDMuNjYsMy4zMyw4Ljk2LjM1LDE3LjkzLjM2LDI2Ljg5LjE5LDEuMTgtLjAyLDMuMzEtMS42OCwzLjM0LTIuNjQuMjYtOC40Mi4xNS0xNi44Ni4xNS0yNS4xOFptNTEuMDktLjE4Yy0xMC42MiwwLTIwLjc2LS4wNi0zMC44OS4xLS45OS4wMi0yLjc4LDEuNDQtMi44LDIuMjQtLjIxLDguNDMtLjEzLDE2Ljg3LS4xMywyNS40MmgzMy44MnYtMjcuNzZabTUyLjE1LjIyYy00Ljk0LDAtOS4yNC0uMDItMTMuNTQsMC02LjQ3LjA0LTE1LjItMi4zNi0xOC43NC44OS0zLjMsMy4wMy0xLjA4LDEyLjA4LTEuMjgsMTguNDctLjA1LDEuNjYtLjUyLDMuNDkuMDIsNC45NC41MSwxLjM3LDIuMDYsMy4zMSwzLjIxLDMuMzUsOC45Ny4zMiwxNy45Ni4zNiwyNi45NC4xNCwxLjE2LS4wMywzLjItMi4wNiwzLjI1LTMuMjMuMjktNy45NS4xNS0xNS45MS4xNS0yNC41N1oiLz4NCiAgPHBhdGggY2xhc3M9ImNscy0xIiBkPSJtMTU4OC44MywxMDIzLjkzYy0xOS42OCwxNzIuMDYtMTYyLjQ0LDI5Ni45Mi0zMTYuMzksMzA1Ljg1LDAtMTguMjgtLjEzLTM2LjU1LjI4LTU0LjguMDMtMS4yNywzLjkyLTMuMjgsNi4xOC0zLjU1LDM3LjktNC40Myw3NC4wOC0xNC42MSwxMDcuNDctMzMuMjMsNzcuOTktNDMuNDgsMTI2LjAzLTEwOS40LDE0NS42Mi0xOTYuMzFxNC4wNi0xOC4wMiwyMi41Mi0xNy45N2MxMS4yOS4wMiwyMi41OCwwLDM0LjMyLDBaIi8+DQogIDxwYXRoIGNsYXNzPSJjbHMtMSIgZD0ibTE1ODkuNTgsOTQ2LjcxYy0xNy41OCwwLTM0LjIyLjA4LTUwLjg1LS4xNi0xLjIxLS4wMi0zLjI0LTIuMTEtMy40Ny0zLjQ4LTkuNTUtNTUuNTUtMzEuODUtMTA1LjQyLTY3Ljc0LTE0OC44Mi00My45OC01My4yLTEwMC4zLTg2Ljg1LTE2Ny4zNi0xMDIuNjItNy43NC0xLjgyLTE1Ljc3LTIuMzUtMjMuNi0zLjg1LTEuNTktLjMtNC4wOC0yLjIzLTQuMS0zLjQ1LS4yNy0xNy42Mi0uMTgtMzUuMjUtLjE4LTUzLjg1LDcxLjU2LDkuNDEsMTMzLjY4LDM4LjA4LDE4OC42Niw4My4yMiw3My42NCw2MC40NywxMTIuODIsMTM5Ljg3LDEyOC42NSwyMzIuOTlaIi8+DQogIDxwYXRoIGNsYXNzPSJjbHMtMSIgZD0ibTExOTUuOTIsMTMzMi40M2MtMjQuNjYtNi4xNS00OC44Ni0xMC42MS03MS45NC0xOC40LTIwLjQ1LTYuOTEtMzkuNzctMTcuMjgtNTkuMjktMjYuNzMtMy42OC0xLjc5LTcuNzgtNi4wNi04LjYxLTkuODYtNS41MS0yNS4yMS0xMC4xOC01MC42LTE1LjYzLTc4LjQ4LDcuODYsNi43MywxMy4yNCwxMS44MSwxOS4wOCwxNi4yNywzOC41MywyOS40Myw4Miw0Ny41NiwxMjkuNjUsNTUuNzUsNS4yMy45LDcuMDcsMi4zOSw2LjkxLDguMDYtLjQ4LDE2LjgtLjE3LDMzLjYyLS4xNyw1My40MVoiLz4NCiAgPHBhdGggY2xhc3M9ImNscy0xIiBkPSJtMTI1Ni4xNCwxMTgzLjk1YzAsNC40MSwwLDguMjIsMCwxMi4wMi0uMDMsNjguNDgtLjExLDEzNi45NSwwLDIwNS40MywwLDQuMzMtLjk5LDUuNzItNS40OSw1LjU2LTEwLjE1LS4zNy0yMC4zMy4xLTMwLjQ3LS4zNS0xLjcyLS4wOC00Ljc1LTMtNC43Ni00LjYyLS4yNi03MS4zMS0uMjYtMTQyLjYxLS4xMi0yMTMuOTIsMC0xLjM3LDIuMDctMy45LDMuMjMtMy45MywxMi4zLS4yOSwyNC42MS0uMTgsMzcuNjEtLjE4WiIvPg0KICA8cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Im0xMjU2LjEyLDY1My4xMmMwLDMzLjMyLS4wOCw2Ni42NS4xLDk5Ljk3LjAyLDQuNDEtMS4xMyw1LjY1LTUuNTcsNS41MS0xMC4xNS0uMzItMjAuMzMuMjEtMzAuNDctLjIyLTEuNzUtLjA3LTQuODItMy4xOS00LjgzLTQuOTEtLjI2LTY3LjE0LS4yOC0xMzQuMjktLjA1LTIwMS40MywwLTEuNjQsMy4wOS00LjYxLDQuODMtNC42OCwxMC4zMS0uNDQsMjAuNjYtLjQ0LDMwLjk3LjAyLDEuNzEuMDgsNC43LDMuMSw0LjcyLDQuNzguMjgsMzMuNjUuMjEsNjcuMzEuMjEsMTAwLjk3LjAzLDAsLjA2LDAsLjEsMFoiLz4NCiAgPHBhdGggY2xhc3M9ImNscy0xIiBkPSJtMTU3OS40NSwxMDA1LjE5Yy0zMC44LDAtNjEuNi0uMDgtOTIuNC4wOS00LjE2LjAyLTUuNC0xLjEtNS4yNy01LjI3LjMxLTkuOTgtLjA3LTE5Ljk4LjMzLTI5Ljk2LjA3LTEuNjIsMi43Mi00LjQ5LDQuMTgtNC41LDYyLjEtLjI2LDEyNC4yLS4yOCwxODYuMy0uMDksMS40NCwwLDQuMDUsMi44NSw0LjExLDQuNDUuMzgsMTAuMTQuNDIsMjAuMzEtLjAzLDMwLjQ1LS4wNywxLjY2LTMuMTIsNC41Ny00LjgyLDQuNTgtMzAuOC4yOC02MS42LjItOTIuNC4ydi4wNFoiLz4NCiAgPHBhdGggY2xhc3M9ImNscy0xIiBkPSJtMTA4Ni42OSw3MjIuODdjMy0yMi4wMiw1Ljk1LTQzLjg0LDkuMDMtNjUuNjMuMTUtMS4wMywxLjI3LTIuMzQsMi4yNi0yLjc4LDMwLjk5LTEzLjc3LDYzLjY3LTIwLjUsOTguMDMtMjMuNywwLDE4LjM4LjEsMzYuMjktLjI2LDU0LjE5LS4wMiwxLjAzLTMuNjMsMi4zNy01Ljc0LDIuOTEtMjIuNDUsNS43LTQ1LjE4LDEwLjQ4LTY3LjMyLDE3LjItMTEuMSwzLjM3LTIxLjE0LDEwLjItMzEuNjYsMTUuNDgtMS42Ny44NC0zLjI5LDEuNzctNC4zNSwyLjMzWiIvPg0KICA8cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Im0xMzU3LjAxLDEwNDUuMTZjMCw3LjQ2LjE4LDE0LjI4LS4yMSwyMS4wNy0uMDUuOTQtMi45MywyLjQ3LTQuNSwyLjQ3LTQ1LjE2LjE2LTkwLjMyLjE2LTEzNS40OC4xNy0yNS44MywwLTUxLjY2LS4xNi03Ny40OS4wNC02LjE3LjA1LTguNTYtMS45NC04LjQ4LTguMzQuMjEtMTUuNDEtLjA0LTE1LjQ1LDE1LjI3LTE1LjQ1LDY4LjQ5LDAsMTM2Ljk4LjAzLDIwNS40Ni4wNCwxLjY2LDAsMy4zMiwwLDUuNDEsMFoiLz4NCiAgPHBhdGggY2xhc3M9ImNscy0xIiBkPSJtMTIxOS40NiwxMDE4Ljk2Yy0yNy40NywwLTU0Ljk0LS4wOS04Mi40LjA4LTQuNi4wMy02LjA4LTEuNTItNi4wOS02LjA0LS4wNC0xOC4xNy0uMTUtMTguMzQsMTguMTUtMTguMzYsNTAuNjEtLjA1LDEwMS4yMS4wOSwxNTEuODIuMDIsNC4zNiwwLDUuOTcsMS4wMiw1LjkxLDUuNzktLjI0LDE4LjQ5LS4wNiwxOC40OS0xOC40NiwxOC40OC0yMi45NywwLTQ1Ljk1LDAtNjguOTIuMDJaIi8+DQo8L3N2Zz4=" alt="SentryStrike" width="34" height="34" style="display: block; width: 34px; height: 34px; border-radius: 9px;"></td>
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
