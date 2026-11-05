#!/usr/bin/env python3
"""Build safe DingTalk issue messages and validate webhook responses."""

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MARKDOWN_META_RE = re.compile(r"([\\`*_!\[\]\(\)#<>])")


class DeliveryRejected(ValueError):
    """DingTalk explicitly rejected the request before accepting a delivery."""


def escape_markdown(value: str) -> str:
    """Escape user-controlled text for a single DingTalk Markdown line."""
    if not isinstance(value, str):
        value = str(value)
    single_line = re.sub(r"[\r\n]+", " ", value)
    single_line = single_line.replace("@", "＠")
    return MARKDOWN_META_RE.sub(r"\\\1", single_line)


def escape_code_span(value: str) -> str:
    """Make text safe inside a single Markdown code span."""
    if not isinstance(value, str):
        value = str(value)
    single_line = re.sub(r"[\r\n]+", " ", value)
    return single_line.replace("`", "＇")


def validate_url(value: str, field: str) -> str:
    """Require an absolute http(s) URL that cannot break a Markdown link."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if value != value.strip():
        raise ValueError(f"{field} must not have leading or trailing whitespace")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in value):
        raise ValueError(f"{field} contains whitespace or control characters")
    if any(ch in value for ch in "()<>"):
        raise ValueError(f"{field} contains characters that are unsafe in Markdown links")
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"{field} must be an absolute http(s) URL")
    return value


def build_issue_markdown(
    *,
    issue_number: str,
    issue_title: str,
    issue_url: str,
    component_label: str,
    author: str,
    owners: str,
    assigned: str,
) -> str:
    """Build a DingTalk message whose Issue link cannot be changed by its title."""
    safe_number = escape_markdown(str(issue_number))
    safe_title = escape_markdown(issue_title)
    safe_url = validate_url(issue_url, "issue_url")
    safe_component = escape_code_span(component_label)
    safe_author = escape_markdown(author)
    safe_owners = escape_markdown(owners)
    safe_assigned = escape_markdown(assigned)
    return (
        "## 🔔 ANOLISA Issue Triage\n\n"
        f"**Issue**: [#{safe_number}]({safe_url})\n\n"
        f"**Title**: {safe_title}\n\n"
        f"**Component**: `{safe_component}`\n\n"
        f"**Author**: {safe_author}\n\n"
        f"**Owners notified**: {safe_owners}\n\n"
        f"**Assigned**: {safe_assigned}\n\n"
        "> 🤖 ANOLISA Issue Bot"
    )


def validate_response(raw_response: str) -> None:
    """Require a JSON object whose DingTalk errcode is zero."""
    try:
        response: Any = json.loads(raw_response)
    except json.JSONDecodeError as error:
        raise ValueError("DingTalk response was not valid JSON") from error

    if not isinstance(response, dict):
        raise ValueError("DingTalk response must be a JSON object")
    if type(response.get("errcode")) is not int:
        raise ValueError("DingTalk response must contain a numeric errcode")
    if response.get("errcode") != 0:
        errcode = response.get("errcode", "missing")
        errmsg = response.get("errmsg", "missing")
        raise DeliveryRejected(
            f"DingTalk notification failed: errcode={errcode}, errmsg={errmsg}"
        )


def build_analysis_markdown(
    *,
    issue_number: int,
    issue_title: str,
    issue_url: str,
    component_label: str,
    priority: str,
    conclusion: str,
    impact: str,
    next_step: str,
    owners: str,
    report_url: str,
    needs_human: bool,
) -> str:
    """Render a bounded analysis card from the controller's structured result."""
    if type(issue_number) is not int:
        raise ValueError("issue_number must be an integer")
    if type(needs_human) is not bool:
        raise ValueError("needs_human must be a boolean")

    safe_issue_url = validate_url(issue_url, "issue_url")
    safe_report_url = validate_url(report_url, "report_url")

    heading = "ANOLISA Issue — needs review" if needs_human else "ANOLISA Issue Analysis"
    fields = {
        "Title": issue_title,
        "Component": component_label,
        "Priority": priority,
        "Conclusion": conclusion,
        "Impact": impact,
        "Next step": next_step,
        "Triagers": owners,
    }
    lines = [f"## {heading}", f"**Issue**: [#{issue_number}]({safe_issue_url})"]
    lines.extend(
        f"**{label}**: {escape_markdown(str(value)[:240])}"
        for label, value in fields.items()
    )
    lines.extend(
        [
            f"[Report]({safe_report_url})",
            "Source analysis; runtime checks are listed in the verification plan.",
        ]
    )
    return "\n\n".join(lines)


def send_markdown(*, webhook: str, secret: str, title: str, text: str) -> None:
    """Send one signed webhook request with a bounded network timeout."""
    parts = urllib.parse.urlsplit(webhook)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)

    if secret:
        timestamp = str(round(time.time() * 1000))
        signature = hmac.new(
            secret.encode(), (timestamp + "\n" + secret).encode(), hashlib.sha256
        ).digest()
        query = [
            (key, value)
            for key, value in query
            if key not in ("timestamp", "sign")
        ]
        query.extend(
            [
                ("timestamp", timestamp),
                ("sign", base64.b64encode(signature).decode()),
            ]
        )

    url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
    payload = json.dumps(
        {
            "msgtype": "markdown",
            "markdown": {"title": title, "text": text},
        }
    ).encode()

    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(65537)
    except urllib.error.HTTPError as error:
        raw_error = b""
        try:
            raw_error = error.read(65537)
        except Exception:
            pass

        if raw_error:
            try:
                validate_response(raw_error.decode("utf-8"))
            except DeliveryRejected as rejected:
                raise DeliveryRejected(str(rejected)) from error
            except (UnicodeDecodeError, ValueError):
                pass

        raise RuntimeError("DingTalk delivery outcome is unknown") from error
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError("DingTalk delivery outcome is unknown") from error

    if len(raw) > 65536:
        raise RuntimeError(
            "DingTalk response exceeded the size limit; outcome is unknown"
        )

    try:
        text_response = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("DingTalk response was not valid UTF-8") from error

    validate_response(text_response)


def require_str(data: Any, key: str) -> str:
    """Read a required string field from the input object."""
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def send_analysis() -> int:
    """Emit a delivery classification without logging webhook credentials."""
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            raise ValueError("input must be a JSON object")

        issue_number = data.get("issue_number")
        if type(issue_number) is not int:
            raise ValueError("issue_number must be an integer")

        needs_human = data.get("needs_human")
        if type(needs_human) is not bool:
            raise ValueError("needs_human must be a boolean")

        analysis_args = {
            "issue_number": issue_number,
            "issue_title": require_str(data, "issue_title"),
            "issue_url": require_str(data, "issue_url"),
            "component_label": require_str(data, "component_label"),
            "priority": require_str(data, "priority"),
            "conclusion": require_str(data, "conclusion"),
            "impact": require_str(data, "impact"),
            "next_step": require_str(data, "next_step"),
            "owners": require_str(data, "owners"),
            "report_url": require_str(data, "report_url"),
            "needs_human": needs_human,
        }
        text = build_analysis_markdown(**analysis_args)
        title = f"Issue Analysis #{issue_number}"
    except (json.JSONDecodeError, ValueError, TypeError) as error:
        print(json.dumps({"status": "invalid_input", "error": str(error)}))
        return 1

    webhook = os.environ.get("DINGTALK_WEBHOOK", "")
    secret = os.environ.get("DINGTALK_SECRET", "")

    if not webhook:
        print(
            json.dumps(
                {
                    "status": "config_error",
                    "error": "DINGTALK_WEBHOOK is not set",
                }
            )
        )
        return 1

    try:
        validate_url(webhook, "DINGTALK_WEBHOOK")
    except ValueError as error:
        print(json.dumps({"status": "config_error", "error": str(error)}))
        return 1

    try:
        send_markdown(webhook=webhook, secret=secret, title=title, text=text)
    except DeliveryRejected:
        print(json.dumps({"status": "rejected"}))
        return 1
    except Exception:
        print(json.dumps({"status": "unknown"}))
        return 1

    print(json.dumps({"status": "delivered"}))
    return 0


def main() -> int:
    """Validate the response supplied on standard input."""
    try:
        validate_response(sys.stdin.read())
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["send-analysis"]:
        raise SystemExit(send_analysis())
    if sys.argv[1:]:
        print("usage: dingtalk_notify.py [send-analysis]", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
