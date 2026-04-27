import base64
import io
import json
import os
import unicodedata
from typing import Any, Optional

import oci
import requests
from fdk import response


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required env: {name}")
    return value


def _get_secret_value(vault_id: str, secret_name: str) -> str:
    signer = oci.auth.signers.get_resource_principals_signer()
    secrets_client = oci.secrets.SecretsClient(config={}, signer=signer)
    bundle = secrets_client.get_secret_bundle_by_name(
        secret_name=secret_name,
        vault_id=vault_id,
        stage="CURRENT",
    ).data
    content = bundle.secret_bundle_content.content
    return base64.b64decode(content).decode("utf-8").strip()


def _parse_payload(raw_text: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload: dict[str, Any] = {}
    message_body: dict[str, Any] = {}

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return payload, message_body
    if not isinstance(parsed, dict):
        return payload, message_body
    payload = parsed

    body = payload.get("body")
    if isinstance(body, str):
        try:
            decoded = json.loads(body)
            if isinstance(decoded, dict):
                message_body = decoded
        except json.JSONDecodeError:
            message_body = {}
    elif isinstance(body, dict):
        message_body = body

    return payload, message_body


def _pick(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _header_safe_value(value: str, fallback: str) -> str:
    candidate = value.strip() or fallback
    try:
        candidate.encode("latin-1")
        return candidate
    except UnicodeEncodeError:
        normalized = (
            unicodedata.normalize("NFKD", candidate)
            .encode("latin-1", "ignore")
            .decode("latin-1")
            .strip()
        )
        if normalized:
            return normalized
        return fallback


def _format_message(raw_text: str) -> tuple[str, str, str, str]:
    payload, body = _parse_payload(raw_text)

    title = _pick(
        payload.get("title"),
        body.get("alarmDisplayName"),
        body.get("displayName"),
        body.get("type"),
        "OCI notification",
    )
    severity = _pick(body.get("severity"), payload.get("severity"))
    lifecycle = _pick(
        body.get("lifecycleState"),
        body.get("status"),
        payload.get("type"),
    )
    region = _pick(body.get("region"), payload.get("region"))
    timestamp = _pick(
        body.get("timestamp"),
        body.get("eventTime"),
        payload.get("timestamp"),
    )
    summary = _pick(
        body.get("body"),
        body.get("summary"),
        body.get("message"),
    )
    header_title = _header_safe_value(title, "OCI notification")

    lines = [f"title: {title}"]
    if severity:
        lines.append(f"severity: {severity}")
    if lifecycle:
        lines.append(f"state: {lifecycle}")
    if region:
        lines.append(f"region: {region}")
    if timestamp:
        lines.append(f"time: {timestamp}")
    if summary:
        lines.append("")
        lines.append(summary)
    else:
        lines.append("")
        lines.append(raw_text[:4000])

    tag = "warning"
    if lifecycle.upper() == "OK":
        tag = "white_check_mark"
    elif severity.upper() in {"CRITICAL", "ERROR"}:
        tag = "rotating_light"

    return title, header_title, "\n".join(lines).strip(), tag


def handler(ctx, data: Optional[io.BytesIO] = None):
    stage = "init"
    try:
        stage = "load_env"
        ntfy_host = _require_env("NTFY_HOST")
        vault_id = _require_env("OCI_VAULT_ID")
        topic_secret_name = _require_env("NTFY_TOPIC_SECRET_NAME")
        token_secret_name = _require_env("NTFY_TOKEN_SECRET_NAME")

        stage = "parse_payload"
        raw_text = (data.getvalue().decode("utf-8") if data else "").strip()
        stage = "read_topic_secret"
        topic = _get_secret_value(vault_id, topic_secret_name)
        stage = "read_token_secret"
        token = _get_secret_value(vault_id, token_secret_name)
        stage = "format_message"
        title, header_title, message, tag = _format_message(raw_text)

        stage = "publish_ntfy"
        publish_response = requests.post(
            f"https://{ntfy_host}/{topic}",
            headers={
                "Authorization": f"Bearer {token}",
                "Title": header_title,
                "Tags": tag,
            },
            data=message.encode("utf-8"),
            timeout=15,
        )
        publish_response.raise_for_status()

        body = {
            "ok": True,
            "title": title,
        }
        return response.Response(
            ctx,
            response_data=json.dumps(body, ensure_ascii=False),
            headers={"Content-Type": "application/json"},
            status_code=200,
        )
    except Exception as exc:  # noqa: BLE001
        print(
            "ntfy-relay handler error:",
            json.dumps(
                {
                    "error_type": type(exc).__name__,
                    "stage": stage,
                    "ntfy_host": locals().get("ntfy_host", ""),
                    "topic_secret_name": locals().get("topic_secret_name", ""),
                    "token_secret_name": locals().get("token_secret_name", ""),
                    "topic_resolved": bool(locals().get("topic", "")),
                },
                ensure_ascii=False,
            ),
        )
        body = {
            "ok": False,
            "error": "internal server error",
            "stage": stage,
            "error_type": type(exc).__name__,
        }
        return response.Response(
            ctx,
            response_data=json.dumps(body, ensure_ascii=False),
            headers={"Content-Type": "application/json"},
            status_code=500,
        )
