import base64
import hashlib
import hmac
import io
import json
import logging
import os
import unicodedata
from typing import Any, Optional
from urllib.parse import urlparse

import oci
import requests
from fdk import response

_LOG_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def _configure_logging() -> logging.Logger:
    level_name = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    level = _LOG_LEVELS.get(level_name, logging.INFO)
    # LOG_LEVEL applies to the relay logger only. Library loggers stay at INFO,
    # because urllib3 logs request paths at DEBUG and the ntfy topic is the path.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logger = logging.getLogger("ntfy-relay")
    logger.setLevel(level)
    return logger


LOGGER = _configure_logging()
NotificationMessage = tuple[str, str, str, str, str, str]
# (connect, read) timeouts for OCI SDK calls, well inside the 30 s function
# timeout; the SDK default read timeout is 60 s.
OCI_CLIENT_TIMEOUT = (5, 10)
ALERTMANAGER_ROUTE_SUFFIX = "/alertmanager"
# Alarm message types from Oracle's Alarm Message Format reference
# (https://docs.oracle.com/en-us/iaas/Content/Monitoring/alarm-message-format.htm).
ALARM_RESOLVED_TYPES = {"OK", "FIRING_TO_OK"}
ALARM_RESET_TYPE = "RESET"


class RelayAuthError(RuntimeError):
    """Request reached the relay through API Gateway without valid credentials."""


def _log_json(level: int, message: str, **fields: Any) -> None:
    LOGGER.log(level, "%s %s", message, json.dumps(fields, ensure_ascii=False, sort_keys=True))


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required env: {name}")
    return value


def _get_secret_value(vault_id: str, secret_name: str) -> str:
    signer = oci.auth.signers.get_resource_principals_signer()
    secrets_client = oci.secrets.SecretsClient(config={}, signer=signer, timeout=OCI_CLIENT_TIMEOUT)
    bundle = secrets_client.get_secret_bundle_by_name(
        secret_name=secret_name,
        vault_id=vault_id,
        stage="CURRENT",
    ).data
    content = bundle.secret_bundle_content.content
    return base64.b64decode(content).decode("utf-8").strip()


def _get_optional_secret_value(vault_id: str, env_name: str) -> str:
    secret_name = os.environ.get(env_name, "").strip()
    if not secret_name:
        return ""
    return _get_secret_value(vault_id, secret_name)


def _ctx_headers(ctx: Any) -> dict[str, str]:
    # HTTPHeaders holds only the caller's headers on API Gateway invocations;
    # Headers merges them with Fn platform headers, so prefer the former.
    for accessor_name in ("HTTPHeaders", "Headers"):
        accessor = getattr(ctx, accessor_name, None)
        if accessor is None:
            continue
        headers = accessor() if callable(accessor) else accessor
        if not headers:
            continue
        return {
            str(key).lower(): ",".join(str(value_part) for value_part in value) if isinstance(value, list) else str(value)
            for key, value in dict(headers).items()
        }
    return {}


def _ctx_request_url(ctx: Any) -> str:
    accessor = getattr(ctx, "RequestURL", None)
    if accessor is None:
        return ""
    request_url = accessor() if callable(accessor) else accessor
    return str(request_url).strip() if request_url else ""


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


def _pick_path(payload: dict[str, Any], *paths: tuple[str, ...]) -> str:
    for path in paths:
        current: Any = payload
        for key in path:
            if not isinstance(current, dict) or key not in current:
                current = None
                break
            current = current[key]
        if isinstance(current, str) and current.strip():
            return current.strip()
    return ""


def _first_dict(items: Any) -> dict[str, Any]:
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                return item
    return {}


def _first_notification(payload: dict[str, Any]) -> dict[str, Any]:
    return _first_dict(payload.get("notifications"))


def _strip_prefix(value: str, prefix: str) -> str:
    if value.lower().startswith(prefix.lower()):
        return value[len(prefix):].strip()
    return value.strip()


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


def _priority_for_tag(tag: str, *, resolved: bool = False) -> str:
    if resolved:
        return "2"
    if tag == "rotating_light":
        return "5"
    if tag == "warning":
        return "4"
    return "3"


def _build_publish_headers(
    *,
    token: str,
    header_title: str,
    tag: str,
    priority: str,
    click: str,
    cf_access_client_id: str,
    cf_access_client_secret: str,
) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Title": header_title,
        "Tags": tag,
        "Priority": priority,
    }
    if click:
        headers["Click"] = click
    if cf_access_client_id and cf_access_client_secret:
        headers["CF-Access-Client-Id"] = cf_access_client_id
        headers["CF-Access-Client-Secret"] = cf_access_client_secret
    return headers


def _verify_bearer_token(headers: dict[str, str], expected_token: str) -> None:
    authorization = headers.get("authorization", "").strip()
    if not authorization.lower().startswith("bearer "):
        raise RelayAuthError("missing bearer authorization header")
    provided = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(provided, expected_token):
        raise RelayAuthError("invalid bearer token")


def _redact(text: str, secret_values: list[str]) -> str:
    for value in secret_values:
        if value:
            text = text.replace(value, "<redacted>")
    return text



def _coerce_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


def _field_value(item: Any, *names: str) -> Any:
    for name in names:
        dict_keys = {name, name.replace("_", "-")}
        if isinstance(item, dict):
            for dict_key in dict_keys:
                if dict_key in item:
                    return item[dict_key]
            continue
        for attr_name in {name, name.replace("-", "_")}:
            if hasattr(item, attr_name):
                return getattr(item, attr_name)
    return None


def _oci_items(result: Any) -> list[Any]:
    data = getattr(result, "data", None)
    if isinstance(data, list):
        return data
    items = getattr(data, "items", None)
    if isinstance(items, list):
        return items
    return []


def _is_osmh_event(raw_text: str) -> bool:
    try:
        payload = json.loads(raw_text) if raw_text else {}
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    event_type = _pick(payload.get("eventType"))
    source = _pick(payload.get("source"))
    return source.lower() == "osmh" or event_type.startswith("com.oraclecloud.osmh.")


OSMH_EVENT_LABELS = {
    "com.oraclecloud.osmh.refreshsoftwareonmanagedinstance": "Refresh software inventory",
    "com.oraclecloud.osmh.createevent.exploitattempt": "Exploit attempt",
    "com.oraclecloud.osmh.createevent.softwareupdate.updateallpackages": "Update all packages job",
    "com.oraclecloud.osmh.createevent.softwareupdate.updatebugfix": "Update bugfix packages job",
    "com.oraclecloud.osmh.createevent.softwareupdate.updateenhancement": "Update enhancement packages job",
    "com.oraclecloud.osmh.createevent.softwareupdate.updateother": "Update other packages job",
    "com.oraclecloud.osmh.createevent.softwareupdate.updatepackages": "Update selected packages job",
    "com.oraclecloud.osmh.createevent.softwareupdate.updatesecurity": "Update security packages job",
}
# Substrings that mark an OSMH event as a failure rather than routine status.
OSMH_FAILURE_MARKERS = ("crash", "fail", "error")


def _osmh_event_label(event_type: str) -> str:
    return OSMH_EVENT_LABELS.get(event_type, _strip_prefix(event_type, "com.oraclecloud.osmh.") or "OSMH event")


def _get_osmh_managed_instance_summary(managed_instance_id: str) -> dict[str, Any]:
    signer = oci.auth.signers.get_resource_principals_signer()
    client = oci.os_management_hub.ManagedInstanceClient(config={}, signer=signer, timeout=OCI_CLIENT_TIMEOUT)
    managed_instance = client.get_managed_instance(managed_instance_id=managed_instance_id).data

    summary = {
        "display_name": _pick(str(_field_value(managed_instance, "display_name") or "")),
        "updates_available": _coerce_int(_field_value(managed_instance, "updates_available")),
        "security_updates_available": _coerce_int(_field_value(managed_instance, "security_updates_available")),
        "bug_updates_available": _coerce_int(_field_value(managed_instance, "bug_updates_available")),
        "enhancement_updates_available": _coerce_int(_field_value(managed_instance, "enhancement_updates_available")),
        "other_updates_available": _coerce_int(_field_value(managed_instance, "other_updates_available")),
        "reboot_required": bool(_field_value(managed_instance, "is_reboot_required")),
        "os_name": _pick(str(_field_value(managed_instance, "os_name") or "")),
        "os_version": _pick(str(_field_value(managed_instance, "os_version") or "")),
    }

    if summary["security_updates_available"] > 0:
        try:
            security_errata = []
            for item in _oci_items(
                client.list_managed_instance_errata(
                    managed_instance_id=managed_instance_id,
                    classification_type=["SECURITY"],
                    limit=2,
                    sort_by="name",
                )
            ):
                advisory_name = _pick(str(_field_value(item, "name") or ""))
                if advisory_name:
                    security_errata.append(advisory_name)
            summary["security_errata"] = security_errata
        except Exception as exc:  # noqa: BLE001
            _log_json(
                logging.WARNING,
                "failed to enrich OSMH security errata",
                managed_instance_id=managed_instance_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )

    if summary["updates_available"] > 0:
        package_kwargs: dict[str, Any] = {
            "managed_instance_id": managed_instance_id,
            "limit": 3,
            "sort_by": "displayName",
        }
        if summary["security_updates_available"] > 0:
            package_kwargs["classification_type"] = ["SECURITY"]
        try:
            package_examples = []
            for item in _oci_items(client.list_managed_instance_updatable_packages(**package_kwargs)):
                package_name = _pick(str(_field_value(item, "name") or ""))
                if package_name:
                    package_examples.append(package_name)
            summary["package_examples"] = package_examples
        except Exception as exc:  # noqa: BLE001
            _log_json(
                logging.WARNING,
                "failed to enrich OSMH package examples",
                managed_instance_id=managed_instance_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )

    return summary


def _format_osmh_message(raw_text: str) -> NotificationMessage:
    payload = json.loads(raw_text) if raw_text else {}
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected OSMH event payload")

    event_type = _pick(payload.get("eventType"))
    event_label = _osmh_event_label(event_type)
    event_time = _pick(payload.get("eventTime"), payload.get("time"))
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    resource_id = _pick(data.get("resourceId"))
    resource_name = _pick(data.get("resourceName"))

    summary: dict[str, Any] = {}
    if resource_id:
        try:
            summary = _get_osmh_managed_instance_summary(resource_id)
        except Exception as exc:  # noqa: BLE001
            _log_json(
                logging.WARNING,
                "failed to enrich OSMH notification",
                event_type=event_type,
                resource_id=resource_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )

    instance_name = _pick(summary.get("display_name"), resource_name, resource_id)
    display_title = f"OCI OSMH | {instance_name} | {event_label}"
    header_title = _header_safe_value(display_title, "OCI OSMH")

    total_updates = _coerce_int(summary.get("updates_available"))
    security_updates = _coerce_int(summary.get("security_updates_available"))
    bug_updates = _coerce_int(summary.get("bug_updates_available"))
    enhancement_updates = _coerce_int(summary.get("enhancement_updates_available"))
    other_updates = _coerce_int(summary.get("other_updates_available"))

    lines = [
        "source: OCI OS Management Hub",
        f"object: {instance_name}",
        f"event: {event_label}",
    ]
    if event_time:
        lines.append(f"time: {event_time}")

    os_name = _pick(str(summary.get("os_name") or ""))
    os_version = _pick(str(summary.get("os_version") or ""))
    if os_name or os_version:
        lines.append(f"os: {' '.join(part for part in [os_name, os_version] if part)}")

    if summary:
        update_parts = [f"{total_updates} total", f"{security_updates} security"]
        if bug_updates:
            update_parts.append(f"{bug_updates} bugfix")
        if enhancement_updates:
            update_parts.append(f"{enhancement_updates} enhancement")
        if other_updates:
            update_parts.append(f"{other_updates} other")
        lines.append(f"updates: {', '.join(update_parts)}")

        security_errata = summary.get("security_errata") if isinstance(summary.get("security_errata"), list) else []
        if security_errata:
            lines.append(f"security_errata: {', '.join(str(item) for item in security_errata[:2])}")

        package_examples = summary.get("package_examples") if isinstance(summary.get("package_examples"), list) else []
        if package_examples:
            lines.append(f"package_examples: {', '.join(str(item) for item in package_examples[:3])}")

        lines.append(f"reboot_required: {'yes' if summary.get('reboot_required') else 'no'}")
    elif resource_id:
        lines.append(f"resource_id: {resource_id}")

    lines.append("")
    if event_type == "com.oraclecloud.osmh.createevent.exploitattempt":
        lines.append("next_hop: review the managed instance and investigate the related security advisory before changing packages.")
    else:
        lines.append("next_hop: review this managed instance in OCI OS Management Hub before scheduling maintenance.")

    tag = "information_source"
    resolved = False
    if event_type == "com.oraclecloud.osmh.createevent.exploitattempt":
        tag = "rotating_light"
    elif any(marker in event_type for marker in OSMH_FAILURE_MARKERS):
        tag = "warning"
    elif event_type in OSMH_EVENT_LABELS and total_updates == 0 and summary:
        # Only known inventory/update events with nothing pending are a recovery.
        tag = "white_check_mark"
        resolved = True

    return display_title, header_title, "\n".join(lines).strip(), tag, _priority_for_tag(tag, resolved=resolved), ""


def _is_cloud_guard_event(raw_text: str) -> bool:
    try:
        payload = json.loads(raw_text) if raw_text else {}
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    return _pick(payload.get("eventType")).startswith("com.oraclecloud.cloudguard.")


def _format_cloud_guard_message(raw_text: str) -> NotificationMessage:
    # Field layout follows Oracle's Cloud Guard event reference
    # (https://docs.oracle.com/iaas/cloud-guard/using/export-notifs-config.htm):
    # data.resourceName is the problem name, data.resourceId the problem OCID,
    # and data.additionalDetails carries the risk level and affected resource.
    payload = json.loads(raw_text) if raw_text else {}
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected Cloud Guard event payload")

    event_type = _pick(payload.get("eventType"))
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    details = data.get("additionalDetails") if isinstance(data.get("additionalDetails"), dict) else {}

    event_label = {
        "com.oraclecloud.cloudguard.problemdetected": "detected",
        "com.oraclecloud.cloudguard.problemdismissed": "dismissed",
        "com.oraclecloud.cloudguard.problemremediated": "resolved",
    }.get(event_type, _strip_prefix(event_type, "com.oraclecloud.cloudguard."))
    risk = _pick(details.get("riskLevel")).upper() or "UNKNOWN"
    problem_name = _pick(data.get("resourceName"), details.get("problemType"), "problem")

    display_title = f"OCI Cloud Guard | {risk} | {problem_name}"
    if event_label != "detected":
        display_title = f"{display_title} | {event_label}"
    header_title = _header_safe_value(display_title, "OCI Cloud Guard")

    lines = [
        "source: OCI Cloud Guard",
        f"problem: {problem_name}",
        f"event: {event_label}",
        f"risk: {risk}",
    ]
    for label, value in (
        ("resource", _pick(details.get("resourceName"))),
        ("resource_type", _pick(details.get("resourceType"))),
        ("compartment", _pick(data.get("compartmentName"))),
        ("region", _pick(details.get("region"))),
        ("status", _pick(details.get("status"))),
        ("first_detected", _pick(details.get("firstDetected"))),
        ("last_detected", _pick(details.get("lastDetected"))),
        ("problem_id", _pick(data.get("resourceId"))),
    ):
        if value:
            lines.append(f"{label}: {value}")
    description = _pick(details.get("problemDescription"))
    recommendation = _pick(details.get("problemRecommendation"))
    if description:
        lines.extend(["", f"description: {description}"])
    if recommendation:
        lines.append(f"recommendation: {recommendation}")

    resolved = event_label in {"dismissed", "resolved"}
    if resolved:
        tag = "white_check_mark"
    elif risk == "CRITICAL":
        tag = "rotating_light"
    elif risk == "HIGH":
        tag = "warning"
    else:
        tag = "information_source"

    return display_title, header_title, "\n".join(lines).strip(), tag, _priority_for_tag(tag, resolved=resolved), ""


def _object_scope(labels: dict[str, Any]) -> str:
    scope_parts = [
        _pick(labels.get("namespace")),
        _pick(labels.get("pod"), labels.get("persistentvolumeclaim"), labels.get("node"), labels.get("instance")),
    ]
    scope_parts = [part for part in scope_parts if part]
    return "/".join(scope_parts)


def _format_message(raw_text: str) -> NotificationMessage:
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
    # Raw alarm messages carry a plain-text "body" and an "alarmMetaData" list
    # with the alarm URL and summary.
    alarm_metadata = _first_dict(payload.get("alarmMetaData"))
    plain_body = payload.get("body") if isinstance(payload.get("body"), str) and not body else ""
    summary = _pick(
        body.get("body"),
        body.get("summary"),
        body.get("message"),
        plain_body,
        alarm_metadata.get("alarmSummary"),
    )
    click = _pick(alarm_metadata.get("alarmUrl"))
    normalized_state = lifecycle.upper() if lifecycle else "EVENT"
    display_title = f"OCI Alarm | {title}"
    if lifecycle:
        display_title = f"{display_title} | {normalized_state}"
    header_title = _header_safe_value(display_title, "OCI Alarm")

    lines = [f"source: OCI Alarm", f"object: {title}"]
    if severity:
        lines.append(f"severity: {severity}")
    if lifecycle:
        lines.append(f"state: {normalized_state}")
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
    if click:
        lines.append("")
        lines.append(f"alarm_url: {click}")

    tag = "warning"
    resolved = False
    if normalized_state in ALARM_RESOLVED_TYPES:
        tag = "white_check_mark"
        resolved = True
    elif normalized_state == ALARM_RESET_TYPE:
        # RESET means the firing metric stream went missing; Oracle asks to
        # check the resource, so keep it a warning rather than a recovery.
        tag = "warning"
    elif severity.upper() in {"CRITICAL", "ERROR"}:
        tag = "rotating_light"

    return display_title, header_title, "\n".join(lines).strip(), tag, _priority_for_tag(tag, resolved=resolved), click



def _verify_hcp_signature(raw_body: bytes, signature: str, token: str) -> None:
    expected = hmac.new(token.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    provided = signature.strip()
    if provided.startswith("sha512="):
        provided = provided.split("=", 1)[1]
    if not hmac.compare_digest(provided.lower(), expected.lower()):
        raise RelayAuthError("invalid HCP Terraform notification signature")


def _merged(fallback: Any, preferred: Any) -> dict[str, Any]:
    merged = dict(fallback) if isinstance(fallback, dict) else {}
    if isinstance(preferred, dict):
        merged.update(preferred)
    return merged


def _format_alertmanager_message(raw_text: str) -> NotificationMessage:
    payload = json.loads(raw_text) if raw_text else {}
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected Alertmanager webhook payload")

    alerts = [item for item in payload.get("alerts", []) if isinstance(item, dict)]
    if not alerts:
        raise RuntimeError("missing Alertmanager alerts")

    first_alert = alerts[0]
    # commonLabels / commonAnnotations hold only values shared by every alert
    # in the group, so fall back to the first alert for anything missing.
    labels = _merged(first_alert.get("labels"), payload.get("commonLabels"))
    annotations = _merged(first_alert.get("annotations"), payload.get("commonAnnotations"))

    status = _pick(payload.get("status"), first_alert.get("status"), "firing").lower()
    severity = _pick(labels.get("severity"), "warning").lower()
    alertname = _pick(labels.get("alertname"), "Alertmanager event")
    scope = _object_scope(labels)
    summary = _pick(annotations.get("summary"))
    description = _pick(annotations.get("description"))
    runbook_url = _pick(annotations.get("runbook_url"))
    generator_url = _pick(first_alert.get("generatorURL"), payload.get("externalURL"))
    alert_count = str(len(alerts))

    display_title = f"Alertmanager | {status.upper()} | {alertname}"
    if scope:
        display_title = f"{display_title} | {scope}"
    header_title = _header_safe_value(display_title, "Alertmanager")

    lines = [f"source: Alertmanager", f"status: {status.upper()}", f"severity: {severity.upper()}", f"alert: {alertname}"]
    if scope:
        lines.append(f"object: {scope}")
    if alert_count != "1":
        lines.append(f"alerts: {alert_count}")
    if summary:
        lines.append("")
        lines.append(summary)
    if description and description != summary:
        lines.append("")
        lines.append(description)
    if runbook_url:
        lines.append("")
        lines.append(f"runbook: {runbook_url}")
    elif generator_url:
        lines.append("")
        lines.append(f"graph: {generator_url}")

    tag = "warning"
    if status == "resolved":
        tag = "white_check_mark"
    elif severity in {"critical", "error"}:
        tag = "rotating_light"

    click = generator_url or runbook_url
    return display_title, header_title, "\n".join(lines).strip(), tag, _priority_for_tag(tag, resolved=status == "resolved"), click


def _format_hcp_message(raw_text: str) -> NotificationMessage:
    payload = json.loads(raw_text) if raw_text else {}
    if not isinstance(payload, dict):
        raise RuntimeError("unexpected HCP Terraform webhook payload")

    notification = _first_notification(payload)
    # HCP Terraform puts the run status in notifications[].run_status
    # (https://developer.hashicorp.com/terraform/cloud-docs/api-docs/notification-configurations/workspace#run-notification-payload).
    run_status = _pick(
        _pick_path(notification, ("run_status",)),
        _pick_path(
            payload,
            ("run_status",),
            ("run", "status"),
            ("data", "attributes", "status"),
        ),
    )
    trigger = _pick(
        _pick_path(payload, ("trigger",), ("run", "trigger"), ("notification_trigger",)),
        _pick_path(notification, ("trigger",)),
    )
    run_message = _pick(
        _pick_path(payload, ("message",), ("run_message",), ("run", "message")),
        _pick_path(notification, ("message",)),
    )
    organization = _pick_path(payload, ("organization_name",), ("organization", "name"))
    workspace = _pick_path(payload, ("workspace_name",), ("workspace", "name"))
    run_url = _pick_path(payload, ("run_url",), ("run", "url"))
    run_id = _pick_path(payload, ("run_id",), ("run", "id"))
    branch = _pick_path(payload, ("vcs_branch_name",), ("run", "vcs_branch_name"), ("vcs", "branch"))
    commit_sha = _pick_path(payload, ("vcs_commit_sha",), ("run", "vcs_commit_sha"), ("vcs", "commit_sha"))
    pull_request_url = _pick_path(payload, ("vcs_pull_request_url",), ("run", "vcs_pull_request_url"), ("vcs", "pull_request_url"))
    notification_configuration_id = _pick_path(payload, ("notification_configuration_id",))

    if trigger.lower() == "verification":
        verification_target = _pick(
            _strip_prefix(run_message, "Verification of"),
            workspace,
            notification_configuration_id,
            "notification",
        )
        title = "HCP Terraform verification"
        header_title = _header_safe_value(
            f"HCP Terraform verification | {verification_target}",
            "HCP Terraform verification",
        )
        lines = []
        if organization:
            lines.append(f"organization: {organization}")
        if workspace:
            lines.append(f"workspace: {workspace}")
        if notification_configuration_id:
            lines.append(f"notification_configuration_id: {notification_configuration_id}")
        lines.append("trigger: verification")
        if run_message:
            lines.append(f"message: {run_message}")
        return title, header_title, "\n".join(lines).strip(), "information_source", "2", ""

    title = _pick(workspace, "HCP Terraform notification")
    status = run_status.lower()
    trigger_name = trigger.lower()
    display_title = f"HCP Terraform | {title}"
    if run_status:
        display_title = f"{display_title} | {run_status}"
    header_title = _header_safe_value(display_title, "HCP Terraform notification")

    lines = [
        f"source: HCP Terraform",
    ]
    if organization:
        lines.append(f"organization: {organization}")
    if workspace:
        lines.append(f"workspace: {workspace}")
    if trigger:
        lines.append(f"trigger: {trigger}")
    if run_status:
        lines.append(f"status: {run_status}")
    if run_id:
        lines.append(f"run_id: {run_id}")
    if branch:
        lines.append(f"branch: {branch}")
    if commit_sha:
        lines.append(f"commit: {commit_sha}")
    if pull_request_url:
        lines.append(f"pull_request: {pull_request_url}")
    if run_url:
        lines.append(f"run_url: {run_url}")
    lines.append("")
    if run_message:
        lines.append(run_message)
    else:
        lines.append(raw_text[:4000] if raw_text else "verification request")

    # Classify on both the run status and the trigger: a run:needs_attention
    # notification can carry a non-error status such as "planned".
    tag = "information_source"
    if "error" in status or "error" in trigger_name:
        tag = "rotating_light"
    elif "attention" in status or "attention" in trigger_name:
        tag = "warning"
    elif status in {"applied", "planned_and_finished", "completed"} or (not status and "completed" in trigger_name):
        tag = "white_check_mark"

    resolved = tag == "white_check_mark"
    return display_title, header_title, "\n".join(lines).strip(), tag, _priority_for_tag(tag, resolved=resolved), run_url


def handler(ctx, data: Optional[io.BytesIO] = None):
    stage = "init"
    try:
        stage = "load_env"
        ntfy_host = _require_env("NTFY_HOST")
        vault_id = _require_env("OCI_VAULT_ID")
        topic_secret_name = _require_env("NTFY_TOPIC_SECRET_NAME")
        token_secret_name = _require_env("NTFY_TOKEN_SECRET_NAME")
        headers = _ctx_headers(ctx)
        request_url = _ctx_request_url(ctx)

        stage = "parse_payload"
        raw_body = data.getvalue() if data else b""
        raw_text = raw_body.decode("utf-8").strip()
        stage = "read_topic_secret"
        topic = _get_secret_value(vault_id, topic_secret_name)
        stage = "read_token_secret"
        token = _get_secret_value(vault_id, token_secret_name)
        stage = "read_cloudflare_access_secrets"
        cf_access_client_id = _get_optional_secret_value(vault_id, "NTFY_CLOUDFLARE_ACCESS_CLIENT_ID_SECRET_NAME")
        cf_access_client_secret = _get_optional_secret_value(
            vault_id,
            "NTFY_CLOUDFLARE_ACCESS_CLIENT_SECRET_SECRET_NAME",
        )
        if bool(cf_access_client_id) != bool(cf_access_client_secret):
            raise RuntimeError("Cloudflare Access client id and secret must be configured together")
        # Only API Gateway sets Fn-Http-Request-Url, so such a request came
        # from the public internet. Every gateway route must authenticate;
        # routes other than Alertmanager fail closed on the HCP signature.
        via_alertmanager_route = bool(request_url) and urlparse(request_url).path.endswith(ALERTMANAGER_ROUTE_SUFFIX)
        if request_url and not via_alertmanager_route:
            stage = "verify_hcp_terraform_signature"
            hcp_secret_name = _require_env("HCP_TERRAFORM_NOTIFICATION_SECRET_NAME")
            hcp_token = _get_secret_value(vault_id, hcp_secret_name)
            signature = headers.get("x-tfe-notification-signature", "").strip()
            if not signature:
                raise RelayAuthError("missing HCP Terraform notification signature header")
            _verify_hcp_signature(raw_body, signature, hcp_token)
            stage = "format_hcp_terraform_message"
            title, header_title, message, tag, priority, click = _format_hcp_message(raw_text)
        elif via_alertmanager_route:
            stage = "verify_alertmanager_bearer_token"
            alertmanager_secret_name = _require_env("ALERTMANAGER_WEBHOOK_TOKEN_SECRET_NAME")
            alertmanager_token = _get_secret_value(vault_id, alertmanager_secret_name)
            _verify_bearer_token(headers, alertmanager_token)
            stage = "format_alertmanager_message"
            title, header_title, message, tag, priority, click = _format_alertmanager_message(raw_text)
        elif _is_osmh_event(raw_text):
            stage = "format_osmh_message"
            title, header_title, message, tag, priority, click = _format_osmh_message(raw_text)
        elif _is_cloud_guard_event(raw_text):
            stage = "format_cloud_guard_message"
            title, header_title, message, tag, priority, click = _format_cloud_guard_message(raw_text)
        else:
            stage = "format_message"
            title, header_title, message, tag, priority, click = _format_message(raw_text)
        _log_json(logging.DEBUG, "prepared ntfy relay payload", stage=stage, title=title, tag=tag, priority=priority, click=click)

        stage = "publish_ntfy"
        publish_headers = _build_publish_headers(
            token=token,
            header_title=header_title,
            tag=tag,
            priority=priority,
            click=click,
            cf_access_client_id=cf_access_client_id,
            cf_access_client_secret=cf_access_client_secret,
        )
        publish_response = requests.post(
            f"https://{ntfy_host}/{topic}",
            headers=publish_headers,
            data=message.encode("utf-8"),
            timeout=15,
        )
        publish_response.raise_for_status()
        _log_json(
            logging.DEBUG,
            "published ntfy relay message",
            stage=stage,
            title=title,
            status_code=publish_response.status_code,
        )

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
        status_code = 401 if isinstance(exc, RelayAuthError) else 500
        secret_values = [
            locals().get(name, "")
            for name in (
                "topic",
                "token",
                "cf_access_client_id",
                "cf_access_client_secret",
                "hcp_token",
                "alertmanager_token",
            )
        ]
        # No traceback: exception text (for example a requests error URL) can
        # carry the topic, so only the redacted message is logged.
        LOGGER.error(
            "ntfy-relay handler error %s",
            json.dumps(
                {
                    "error_type": type(exc).__name__,
                    "stage": stage,
                    "ntfy_host": locals().get("ntfy_host", ""),
                    "topic_secret_name": locals().get("topic_secret_name", ""),
                    "token_secret_name": locals().get("token_secret_name", ""),
                    "topic_resolved": bool(locals().get("topic", "")),
                    "raw_text_present": bool(locals().get("raw_text", "")),
                    "exception_message": _redact(str(exc), secret_values),
                    "http_status": getattr(getattr(exc, "response", None), "status_code", None),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
        )
        body = {
            "ok": False,
            "error": "unauthorized" if status_code == 401 else "internal server error",
            "stage": stage,
            "error_type": type(exc).__name__,
        }
        return response.Response(
            ctx,
            response_data=json.dumps(body, ensure_ascii=False),
            headers={"Content-Type": "application/json"},
            status_code=status_code,
        )
