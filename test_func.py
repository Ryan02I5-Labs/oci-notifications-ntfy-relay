import hashlib
import hmac
import io
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


sys.modules.setdefault("oci", types.SimpleNamespace(auth=types.SimpleNamespace(signers=types.SimpleNamespace())))
sys.modules.setdefault("requests", types.SimpleNamespace())
sys.modules.setdefault(
    "fdk",
    types.SimpleNamespace(response=types.SimpleNamespace(Response=object)),
)

MODULE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MODULE_DIR))

import func  # noqa: E402


class FormatMessageTests(unittest.TestCase):
    # Payload shape from Oracle's Cloud Guard "Detected - Problem Example".
    CLOUD_GUARD_EVENT = {
        "eventType": "com.oraclecloud.cloudguard.problemdetected",
        "cloudEventsVersion": "0.1",
        "eventTypeVersion": "2.0",
        "source": "CloudGuardResponderEngine",
        "eventTime": "2026-10-29T04:00:00Z",
        "contentType": "application/json",
        "data": {
            "compartmentId": "ocid1.compartment.oc1..example",
            "compartmentName": "example",
            "resourceName": "Bucket is public",
            "resourceId": "ocid1.cloudguardproblem.oc1.ap-osaka-1.example",
            "additionalDetails": {
                "tenantId": "ocid1.tenancy.oc1..example",
                "problemDescription": "Object Storage supports anonymous access.",
                "riskLevel": "CRITICAL",
                "problemRecommendation": "Ensure the bucket is not public.",
                "status": "OPEN",
                "problemType": "CONFIG_CHANGE",
                "resourceName": "example-bucket",
                "resourceId": "ocid1.bucket.oc1.ap-osaka-1.example",
                "resourceType": "Bucket",
                "targetId": "ocid1.cloudguardtarget.oc1..example",
                "labels": "CIS_OCI_V1.1_OBJECTSTORAGE",
                "firstDetected": "2026-10-29T03:58:00.000Z",
                "lastDetected": "2026-10-29T03:58:00.000Z",
                "region": "ap-osaka-1",
            },
        },
        "eventID": "example",
    }

    def test_identifies_cloud_guard_event_by_event_type(self):
        self.assertTrue(func._is_cloud_guard_event(json.dumps(self.CLOUD_GUARD_EVENT)))
        self.assertFalse(func._is_cloud_guard_event(json.dumps({"eventType": "com.oraclecloud.osmh.createevent.exploitattempt"})))
        self.assertFalse(func._is_osmh_event(json.dumps(self.CLOUD_GUARD_EVENT)))

    def test_formats_cloud_guard_problem_detected(self):
        title, header_title, message, tag, priority, click = func._format_cloud_guard_message(json.dumps(self.CLOUD_GUARD_EVENT))

        self.assertEqual(title, "OCI Cloud Guard | CRITICAL | Bucket is public")
        self.assertEqual(header_title, title)
        self.assertIn("resource: example-bucket", message)
        self.assertIn("resource_type: Bucket", message)
        self.assertIn("region: ap-osaka-1", message)
        self.assertIn("problem_id: ocid1.cloudguardproblem.oc1.ap-osaka-1.example", message)
        self.assertIn("recommendation: Ensure the bucket is not public.", message)
        self.assertNotIn('"eventType"', message)
        self.assertEqual(tag, "rotating_light")
        self.assertEqual(priority, "5")
        self.assertEqual(click, "")

    def test_formats_cloud_guard_high_and_resolved_events(self):
        high = json.loads(json.dumps(self.CLOUD_GUARD_EVENT))
        high["data"]["additionalDetails"]["riskLevel"] = "HIGH"
        _, _, _, tag, priority, _ = func._format_cloud_guard_message(json.dumps(high))
        self.assertEqual((tag, priority), ("warning", "4"))

        remediated = json.loads(json.dumps(self.CLOUD_GUARD_EVENT))
        remediated["eventType"] = "com.oraclecloud.cloudguard.problemremediated"
        title, _, _, tag, priority, _ = func._format_cloud_guard_message(json.dumps(remediated))
        self.assertTrue(title.endswith("| resolved"))
        self.assertEqual((tag, priority), ("white_check_mark", "2"))

    def test_verifies_hcp_signature_against_exact_request_body(self):
        token = "test-token"
        raw_body = b'{"payload_version":1}\n'
        signature = hmac.new(token.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()

        func._verify_hcp_signature(raw_body, signature, token)

        stripped_signature = hmac.new(token.encode("utf-8"), raw_body.strip(), hashlib.sha512).hexdigest()
        with self.assertRaises(RuntimeError):
            func._verify_hcp_signature(raw_body, stripped_signature, token)

    def test_identifies_osmh_event_by_source_and_event_type(self):
        payload = {
            "source": "osmh",
            "eventType": "com.oraclecloud.osmh.refreshsoftwareonmanagedinstance",
        }

        self.assertTrue(func._is_osmh_event(json.dumps(payload)))

    def test_build_publish_headers_omits_click_when_empty(self):
        headers = func._build_publish_headers(
            token="token-123",
            header_title="HCP Terraform verification",
            tag="information_source",
            priority="2",
            click="",
            cf_access_client_id="",
            cf_access_client_secret="",
        )

        self.assertEqual(headers["Authorization"], "Bearer token-123")
        self.assertEqual(headers["Title"], "HCP Terraform verification")
        self.assertEqual(headers["Tags"], "information_source")
        self.assertEqual(headers["Priority"], "2")
        self.assertNotIn("Click", headers)
        self.assertNotIn("CF-Access-Client-Id", headers)

    def test_build_publish_headers_includes_click_and_access_headers(self):
        headers = func._build_publish_headers(
            token="token-123",
            header_title="Alertmanager | FIRING | KubePodCrashLooping | monitoring/loki-0",
            tag="warning",
            priority="4",
            click="https://runbooks.prometheus-operator.dev/runbooks/kubernetes/kubepodcrashlooping",
            cf_access_client_id="client-id",
            cf_access_client_secret="client-secret",
        )

        self.assertEqual(
            headers["Click"],
            "https://runbooks.prometheus-operator.dev/runbooks/kubernetes/kubepodcrashlooping",
        )
        self.assertEqual(headers["CF-Access-Client-Id"], "client-id")
        self.assertEqual(headers["CF-Access-Client-Secret"], "client-secret")

    def test_formats_hcp_verification_payload_compactly(self):
        payload = {
            "payload_version": 1,
            "notification_configuration_id": "nc-8cizDrtSpBkh5cUo",
            "run_url": None,
            "run_id": None,
            "run_message": None,
            "workspace_name": None,
            "organization_name": None,
            "notifications": [
                {
                    "message": "Verification of example notification",
                    "trigger": "verification",
                    "run_status": None,
                }
            ],
        }
        title, header_title, message, tag, priority, click = func._format_hcp_message(json.dumps(payload))

        self.assertEqual(title, "HCP Terraform verification")
        self.assertEqual(
            header_title,
            "HCP Terraform verification | example notification",
        )
        self.assertNotIn("title: HCP Terraform verification", message)
        self.assertIn("trigger: verification", message)
        self.assertIn("notification_configuration_id: nc-8cizDrtSpBkh5cUo", message)
        self.assertIn("message: Verification of example notification", message)
        self.assertNotIn('"payload_version"', message)
        self.assertEqual(tag, "information_source")
        self.assertEqual(priority, "2")
        self.assertEqual(click, "")

    def test_formats_hcp_run_payload_with_run_context(self):
        payload = {
            "workspace_name": "example-workspace",
            "organization_name": "example-org",
            "trigger": "run:completed",
            "run_status": "planned_and_finished",
            "run_id": "run-example",
            "run_url": "https://app.terraform.io/app/example-org/example-workspace/runs/run-example",
            "run_message": "Manual verification run for ntfy notification wiring",
            "vcs_branch_name": "main",
            "vcs_commit_sha": "067da5131047408ebf88a329b8eba5a5b373cf8b",
        }
        title, header_title, message, tag, priority, click = func._format_hcp_message(json.dumps(payload))

        self.assertEqual(title, "HCP Terraform | example-workspace | planned_and_finished")
        self.assertEqual(
            header_title,
            "HCP Terraform | example-workspace | planned_and_finished",
        )
        self.assertIn("status: planned_and_finished", message)
        self.assertIn("run_url: https://app.terraform.io/app/example-org/example-workspace/runs/run-example", message)
        self.assertIn("commit: 067da5131047408ebf88a329b8eba5a5b373cf8b", message)
        self.assertEqual(tag, "white_check_mark")
        self.assertEqual(priority, "2")
        self.assertEqual(
            click,
            "https://app.terraform.io/app/example-org/example-workspace/runs/run-example",
        )

    def test_formats_oci_notification_without_regression(self):
        payload = {
            "title": "example | server | Backup Freshness",
            "body": json.dumps(
                {
                    "severity": "CRITICAL",
                    "status": "FIRING",
                    "timestamp": "2026-05-19T19:00:00+09:00",
                    "body": "backup freshness alert",
                }
            ),
        }
        title, header_title, message, tag, priority, click = func._format_message(json.dumps(payload))

        self.assertEqual(title, "OCI Alarm | example | server | Backup Freshness | FIRING")
        self.assertEqual(header_title, "OCI Alarm | example | server | Backup Freshness | FIRING")
        self.assertIn("severity: CRITICAL", message)
        self.assertIn("state: FIRING", message)
        self.assertIn("backup freshness alert", message)
        self.assertEqual(tag, "rotating_light")
        self.assertEqual(priority, "5")
        self.assertEqual(click, "")

    def test_formats_osmh_refresh_event_with_managed_instance_summary(self):
        payload = {
            "source": "osmh",
            "eventType": "com.oraclecloud.osmh.refreshsoftwareonmanagedinstance",
            "eventTime": "2026-06-19T06:36:51Z",
            "data": {
                "resourceId": "ocid1.instance.oc1.ap-osaka-1.example",
                "resourceName": "example-worker-01",
            },
        }

        with patch.object(
            func,
            "_get_osmh_managed_instance_summary",
            return_value={
                "display_name": "example-worker-01",
                "updates_available": 12,
                "security_updates_available": 1,
                "bug_updates_available": 11,
                "enhancement_updates_available": 0,
                "other_updates_available": 0,
                "reboot_required": False,
                "os_name": "Oracle Linux Server",
                "os_version": "9",
                "security_errata": ["ELSA-2026-50319"],
                "package_examples": ["kernel-uek", "kernel-uek-core", "ksplice-tools"],
            },
        ):
            title, header_title, message, tag, priority, click = func._format_osmh_message(json.dumps(payload))

        self.assertEqual(
            title,
            "OCI OSMH | example-worker-01 | Refresh software inventory",
        )
        self.assertEqual(header_title, title)
        self.assertIn("source: OCI OS Management Hub", message)
        self.assertIn("object: example-worker-01", message)
        self.assertIn("event: Refresh software inventory", message)
        self.assertIn("updates: 12 total, 1 security, 11 bugfix", message)
        self.assertIn("security_errata: ELSA-2026-50319", message)
        self.assertIn("package_examples: kernel-uek, kernel-uek-core, ksplice-tools", message)
        self.assertIn("next_hop: review this managed instance in OCI OS Management Hub before scheduling maintenance.", message)
        self.assertNotIn('"eventType"', message)
        self.assertEqual(tag, "information_source")
        self.assertEqual(priority, "3")
        self.assertEqual(click, "")

    def test_formats_osmh_refresh_event_without_updates_as_check_mark(self):
        payload = {
            "source": "osmh",
            "eventType": "com.oraclecloud.osmh.refreshsoftwareonmanagedinstance",
            "eventTime": "2026-06-19T08:36:51Z",
            "data": {
                "resourceId": "ocid1.instance.oc1.ap-osaka-1.example",
                "resourceName": "example-server-osa1-01",
            },
        }

        with patch.object(
            func,
            "_get_osmh_managed_instance_summary",
            return_value={
                "display_name": "example-server-osa1-01",
                "updates_available": 0,
                "security_updates_available": 0,
                "bug_updates_available": 0,
                "enhancement_updates_available": 0,
                "other_updates_available": 0,
                "reboot_required": False,
                "os_name": "Oracle Linux Server",
                "os_version": "9",
            },
        ):
            title, header_title, message, tag, priority, click = func._format_osmh_message(json.dumps(payload))

        self.assertEqual(
            title,
            "OCI OSMH | example-server-osa1-01 | Refresh software inventory",
        )
        self.assertEqual(header_title, title)
        self.assertIn("updates: 0 total, 0 security", message)
        self.assertEqual(tag, "white_check_mark")
        self.assertEqual(priority, "2")
        self.assertEqual(click, "")

    def test_formats_osmh_exploit_attempt_without_raw_json_fallback(self):
        payload = {
            "source": "osmh",
            "eventType": "com.oraclecloud.osmh.createevent.exploitattempt",
            "eventTime": "2026-06-19T07:05:00Z",
            "data": {
                "resourceId": "ocid1.instance.oc1.ap-osaka-1.example",
                "resourceName": "example-edge-osa1-01",
            },
        }

        with patch.object(
            func,
            "_get_osmh_managed_instance_summary",
            side_effect=RuntimeError("permission denied"),
        ):
            title, header_title, message, tag, priority, click = func._format_osmh_message(json.dumps(payload))

        self.assertEqual(
            title,
            "OCI OSMH | example-edge-osa1-01 | Exploit attempt",
        )
        self.assertEqual(header_title, title)
        self.assertIn("event: Exploit attempt", message)
        self.assertIn("resource_id: ocid1.instance.oc1.ap-osaka-1.example", message)
        self.assertIn("next_hop: review the managed instance and investigate the related security advisory before changing packages.", message)
        self.assertNotIn('"eventType"', message)
        self.assertEqual(tag, "rotating_light")
        self.assertEqual(priority, "5")
        self.assertEqual(click, "")

    def test_get_osmh_managed_instance_summary_uses_list_classification_type(self):
        calls = {}

        class FakeClient:
            def __init__(self, config, signer, timeout):
                calls["config"] = config
                calls["signer"] = signer
                calls["timeout"] = timeout

            def get_managed_instance(self, managed_instance_id):
                calls["managed_instance_id"] = managed_instance_id
                return types.SimpleNamespace(
                    data=types.SimpleNamespace(
                        display_name="example-worker-01",
                        updates_available=12,
                        security_updates_available=2,
                        bug_updates_available=10,
                        enhancement_updates_available=0,
                        other_updates_available=0,
                        is_reboot_required=False,
                        os_name="oraclelinux",
                        os_version="9.7",
                    )
                )

            def list_managed_instance_errata(self, **kwargs):
                calls["errata_kwargs"] = kwargs
                return types.SimpleNamespace(
                    data=types.SimpleNamespace(items=[types.SimpleNamespace(name="ELSA-2026-50319")])
                )

            def list_managed_instance_updatable_packages(self, **kwargs):
                calls["package_kwargs"] = kwargs
                return types.SimpleNamespace(
                    data=types.SimpleNamespace(
                        items=[
                            types.SimpleNamespace(name="kernel-uek"),
                            types.SimpleNamespace(name="kernel-uek-core"),
                        ]
                    )
                )

        with patch.object(
            func.oci.auth.signers,
            "get_resource_principals_signer",
            return_value="rp-signer",
            create=True,
        ), patch.object(
            func.oci,
            "os_management_hub",
            types.SimpleNamespace(ManagedInstanceClient=FakeClient),
            create=True,
        ):
            summary = func._get_osmh_managed_instance_summary("ocid1.instance.oc1.ap-osaka-1.example")

        self.assertEqual(summary["display_name"], "example-worker-01")
        self.assertEqual(summary["updates_available"], 12)
        self.assertEqual(summary["security_errata"], ["ELSA-2026-50319"])
        self.assertEqual(summary["package_examples"], ["kernel-uek", "kernel-uek-core"])
        self.assertEqual(calls["managed_instance_id"], "ocid1.instance.oc1.ap-osaka-1.example")
        self.assertEqual(calls["errata_kwargs"]["classification_type"], ["SECURITY"])
        self.assertEqual(calls["package_kwargs"]["classification_type"], ["SECURITY"])
        self.assertEqual(calls["timeout"], func.OCI_CLIENT_TIMEOUT)

    def test_get_osmh_managed_instance_summary_keeps_base_fields_when_optional_enrich_fails(self):
        class FakeClient:
            def __init__(self, config, signer, timeout):
                pass

            def get_managed_instance(self, managed_instance_id):
                return types.SimpleNamespace(
                    data=types.SimpleNamespace(
                        display_name="example-worker-01",
                        updates_available=12,
                        security_updates_available=2,
                        bug_updates_available=10,
                        enhancement_updates_available=0,
                        other_updates_available=0,
                        is_reboot_required=False,
                        os_name="oraclelinux",
                        os_version="9.7",
                    )
                )

            def list_managed_instance_errata(self, **kwargs):
                raise RuntimeError("errata unavailable")

            def list_managed_instance_updatable_packages(self, **kwargs):
                raise RuntimeError("packages unavailable")

        with patch.object(
            func.oci.auth.signers,
            "get_resource_principals_signer",
            return_value="rp-signer",
            create=True,
        ), patch.object(
            func.oci,
            "os_management_hub",
            types.SimpleNamespace(ManagedInstanceClient=FakeClient),
            create=True,
        ), patch.object(func, "_log_json") as log_json:
            summary = func._get_osmh_managed_instance_summary("ocid1.instance.oc1.ap-osaka-1.example")

        self.assertEqual(summary["display_name"], "example-worker-01")
        self.assertEqual(summary["updates_available"], 12)
        self.assertEqual(summary["security_updates_available"], 2)
        self.assertNotIn("security_errata", summary)
        self.assertNotIn("package_examples", summary)
        self.assertEqual(log_json.call_count, 2)

    def test_formats_alertmanager_payload_compactly(self):
        payload = {
            "receiver": "ntfy",
            "status": "firing",
            "commonLabels": {
                "alertname": "KubePodCrashLooping",
                "namespace": "monitoring",
                "pod": "loki-0",
                "severity": "warning",
            },
            "commonAnnotations": {
                "summary": "Pod is crash looping.",
                "description": "Pod monitoring/loki-0 is in waiting state (reason: CrashLoopBackOff)",
                "runbook_url": "https://runbooks.prometheus-operator.dev/runbooks/kubernetes/kubepodcrashlooping",
            },
            "alerts": [
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "KubePodCrashLooping",
                        "namespace": "monitoring",
                        "pod": "loki-0",
                        "severity": "warning",
                    },
                    "annotations": {
                        "summary": "Pod is crash looping.",
                        "description": "Pod monitoring/loki-0 is in waiting state (reason: CrashLoopBackOff)",
                        "runbook_url": "https://runbooks.prometheus-operator.dev/runbooks/kubernetes/kubepodcrashlooping",
                    },
                    "generatorURL": "http://kps-prometheus.monitoring:9090/graph?g0.expr=test",
                }
            ],
        }

        title, header_title, message, tag, priority, click = func._format_alertmanager_message(json.dumps(payload))

        self.assertEqual(title, "Alertmanager | FIRING | KubePodCrashLooping | monitoring/loki-0")
        self.assertEqual(header_title, "Alertmanager | FIRING | KubePodCrashLooping | monitoring/loki-0")
        self.assertIn("source: Alertmanager", message)
        self.assertIn("status: FIRING", message)
        self.assertIn("object: monitoring/loki-0", message)
        self.assertIn("runbook: https://runbooks.prometheus-operator.dev/runbooks/kubernetes/kubepodcrashlooping", message)
        self.assertEqual(tag, "warning")
        self.assertEqual(priority, "4")
        self.assertEqual(click, "http://kps-prometheus.monitoring:9090/graph?g0.expr=test")

    # Raw alarm message from Oracle's Alarm Message Format reference
    # (https://docs.oracle.com/en-us/iaas/Content/Monitoring/alarm-message-format.htm).
    @staticmethod
    def _raw_alarm(message_type, status):
        return {
            "dedupekey": "example",
            "title": "example | ntfy-relay | Relay Errors",
            "body": "ntfy relay function returned errors.",
            "type": message_type,
            "severity": "CRITICAL",
            "timestampEpochMillis": 1761818400000,
            "timestamp": "2026-10-30T10:00:00Z",
            "version": "1.5",
            "alarmMetaData": [
                {
                    "id": "ocid1.alarm.oc1..example",
                    "status": status,
                    "severity": "CRITICAL",
                    "namespace": "oci_faas",
                    "query": "FunctionResponseCount[5m].sum() > 0",
                    "totalMetricsFiring": 1,
                    "dimensions": [],
                    "metricValues": [],
                    "alarmUrl": "https://cloud.oracle.com/monitoring/alarms/example",
                    "alarmSummary": "Alarm is in a FIRING state",
                    "notificationType": "Grouped messages across metric streams",
                }
            ],
        }

    def test_formats_raw_alarm_firing_with_body_and_alarm_url(self):
        title, _, message, tag, priority, click = func._format_message(json.dumps(self._raw_alarm("OK_TO_FIRING", "FIRING")))

        self.assertEqual(title, "OCI Alarm | example | ntfy-relay | Relay Errors | OK_TO_FIRING")
        self.assertIn("ntfy relay function returned errors.", message)
        self.assertNotIn("alarmMetaData", message)
        self.assertEqual(tag, "rotating_light")
        self.assertEqual(priority, "5")
        self.assertEqual(click, "https://cloud.oracle.com/monitoring/alarms/example")

    def test_formats_raw_alarm_recovery_as_resolved(self):
        _, _, _, tag, priority, _ = func._format_message(json.dumps(self._raw_alarm("FIRING_TO_OK", "OK")))

        self.assertEqual(tag, "white_check_mark")
        self.assertEqual(priority, "2")

    def test_formats_raw_alarm_reset_as_warning(self):
        _, _, _, tag, priority, _ = func._format_message(json.dumps(self._raw_alarm("RESET", "OK")))

        self.assertEqual(tag, "warning")
        self.assertEqual(priority, "4")


    def test_formats_hcp_official_payload_status_from_notifications(self):
        # Shape from HashiCorp's run notification payload reference.
        payload = {
            "payload_version": 1,
            "notification_configuration_id": "nc-example",
            "run_url": "https://app.terraform.io/app/example-org/example-workspace/runs/run-example",
            "run_id": "run-example",
            "run_message": "Queued manually",
            "workspace_name": "example-workspace",
            "organization_name": "example-org",
            "notifications": [
                {
                    "message": "Run Applied",
                    "trigger": "run:completed",
                    "run_status": "applied",
                    "run_updated_at": "2026-10-31T00:00:00.000Z",
                    "run_updated_by": "example-user",
                }
            ],
        }
        title, _, message, tag, priority, _ = func._format_hcp_message(json.dumps(payload))

        self.assertEqual(title, "HCP Terraform | example-workspace | applied")
        self.assertIn("status: applied", message)
        self.assertEqual(tag, "white_check_mark")
        self.assertEqual(priority, "2")

    def test_hcp_needs_attention_trigger_wins_over_planned_status(self):
        payload = {
            "workspace_name": "example-workspace",
            "notifications": [{"trigger": "run:needs_attention", "run_status": "planned", "message": "Run Needs Attention"}],
        }
        _, _, _, tag, priority, _ = func._format_hcp_message(json.dumps(payload))

        self.assertEqual(tag, "warning")
        self.assertEqual(priority, "4")

    def test_osmh_failure_event_without_updates_is_not_a_recovery(self):
        event = {
            "eventType": "com.oraclecloud.osmh.createevent.reboot.rebootfailed",
            "source": "osmh",
            "data": {"resourceId": "ocid1.instance.oc1..example", "resourceName": "example-worker-01"},
        }
        summary = {"display_name": "example-worker-01", "updates_available": 0}
        with patch.object(func, "_get_osmh_managed_instance_summary", return_value=summary):
            _, _, _, tag, priority, _ = func._format_osmh_message(json.dumps(event))

        self.assertEqual(tag, "warning")
        self.assertEqual(priority, "4")

    def test_unmapped_osmh_event_keeps_its_type(self):
        self.assertEqual(func._osmh_event_label("com.oraclecloud.osmh.createevent.kernelcrash"), "createevent.kernelcrash")

    def test_alertmanager_group_keeps_first_alert_details(self):
        payload = {
            "receiver": "ntfy",
            "status": "firing",
            "commonLabels": {"alertname": "KubePodCrashLooping", "severity": "warning"},
            "commonAnnotations": {},
            "alerts": [
                {"labels": {"namespace": "monitoring", "pod": "a-0"}, "annotations": {"summary": "a-0 is crash looping"}},
                {"labels": {"namespace": "monitoring", "pod": "b-0"}, "annotations": {"summary": "b-0 is crash looping"}},
            ],
        }
        _, _, message, _, _, _ = func._format_alertmanager_message(json.dumps(payload))

        self.assertIn("a-0 is crash looping", message)
        self.assertIn("alerts: 2", message)

    def test_debug_log_level_does_not_enable_library_debug_logs(self):
        with patch.dict(func.os.environ, {"LOG_LEVEL": "DEBUG"}):
            logger = func._configure_logging()

        self.assertEqual(logger.level, func.logging.DEBUG)
        self.assertFalse(func.logging.getLogger("urllib3").isEnabledFor(func.logging.DEBUG))

    def test_library_debug_logs_stay_off_when_fdk_sets_root_debug(self):
        root = func.logging.getLogger()
        previous = root.level
        try:
            with patch.dict(func.os.environ, {"LOG_LEVEL": "DEBUG"}):
                func._configure_logging()
            # The Fn FDK does this after the function module is imported.
            root.setLevel(func.logging.DEBUG)
            for name in ("urllib3", "urllib3.connectionpool", "requests", "oci"):
                self.assertFalse(func.logging.getLogger(name).isEnabledFor(func.logging.DEBUG), name)
        finally:
            root.setLevel(previous)

    def test_oci_clients_use_bounded_timeouts(self):
        seen = {}

        class FakeSecretsClient:
            def __init__(self, config, signer, timeout):
                seen["timeout"] = timeout

            def get_secret_bundle_by_name(self, **kwargs):
                content = types.SimpleNamespace(content="dmFsdWU=")
                return types.SimpleNamespace(data=types.SimpleNamespace(secret_bundle_content=content))

        fake_oci = types.SimpleNamespace(
            auth=types.SimpleNamespace(signers=types.SimpleNamespace(get_resource_principals_signer=lambda: object())),
            secrets=types.SimpleNamespace(SecretsClient=FakeSecretsClient),
        )
        with patch.object(func, "oci", fake_oci):
            self.assertEqual(func._get_secret_value("vault", "name"), "value")

        self.assertEqual(seen["timeout"], func.OCI_CLIENT_TIMEOUT)
        self.assertLess(sum(func.OCI_CLIENT_TIMEOUT), 30)


class HandlerTests(unittest.TestCase):
    SECRETS = {
        "topic-secret": "secret-topic",
        "token-secret": "secret-token",
        "hcp-secret": "hcp-hmac-key",
        "am-secret": "am-bearer",
    }
    ENV = {
        "NTFY_HOST": "ntfy.example.com",
        "OCI_VAULT_ID": "ocid1.vault.oc1..example",
        "NTFY_TOPIC_SECRET_NAME": "topic-secret",
        "NTFY_TOKEN_SECRET_NAME": "token-secret",
        "HCP_TERRAFORM_NOTIFICATION_SECRET_NAME": "hcp-secret",
        "ALERTMANAGER_WEBHOOK_TOKEN_SECRET_NAME": "am-secret",
    }

    class Ctx:
        def __init__(self, request_url=None, headers=None):
            self._request_url = request_url
            self._headers = headers or {}

        def RequestURL(self):
            return self._request_url

        def HTTPHeaders(self):
            return self._headers

        def Headers(self):
            return {}

    def _invoke(self, body, *, request_url=None, headers=None, post=None):
        published = []

        def fake_post(url, headers, data, timeout):
            published.append(url)
            if post:
                return post(url)
            return types.SimpleNamespace(status_code=200, raise_for_status=lambda: None)

        def fake_response(ctx, response_data, headers, status_code):
            return {"status_code": status_code, "body": json.loads(response_data)}

        raw = body.encode("utf-8")
        with patch.dict(func.os.environ, self.ENV, clear=False), patch.object(
            func, "_get_secret_value", side_effect=lambda vault_id, name: self.SECRETS[name]
        ), patch.object(func, "requests", types.SimpleNamespace(post=fake_post)), patch.object(
            func, "response", types.SimpleNamespace(Response=fake_response)
        ):
            result = func.handler(self.Ctx(request_url, headers), io.BytesIO(raw))
        return result, published

    def test_gateway_request_without_signature_is_rejected(self):
        alarm = json.dumps({"title": "spoofed", "body": "click here"})
        result, published = self._invoke(alarm, request_url="/webhooks/hcp-terraform-learning")

        self.assertEqual(result["status_code"], 401)
        self.assertEqual(published, [])

    def test_gateway_unknown_route_fails_closed(self):
        result, published = self._invoke("{}", request_url="/webhooks/other")

        self.assertEqual(result["status_code"], 401)
        self.assertEqual(published, [])

    def test_gateway_hcp_request_with_valid_signature_is_published(self):
        body = json.dumps({"payload_version": 1, "workspace_name": "ws", "notifications": [{"trigger": "run:completed"}]})
        signature = hmac.new(b"hcp-hmac-key", body.encode("utf-8"), hashlib.sha512).hexdigest()
        result, published = self._invoke(
            body,
            request_url="/webhooks/hcp-terraform-learning",
            headers={"x-tfe-notification-signature": signature},
        )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(published, ["https://ntfy.example.com/secret-topic"])

    def test_gateway_alertmanager_requires_bearer_token(self):
        body = json.dumps({"receiver": "ntfy", "status": "firing", "alerts": [{"labels": {"alertname": "X"}}]})
        rejected, published = self._invoke(body, request_url="/webhooks/alertmanager")
        accepted, _ = self._invoke(
            body,
            request_url="/webhooks/alertmanager",
            headers={"authorization": "Bearer am-bearer"},
        )

        self.assertEqual(rejected["status_code"], 401)
        self.assertEqual(published, [])
        self.assertEqual(accepted["status_code"], 200)

    def test_notifications_invocation_without_gateway_is_published(self):
        result, published = self._invoke(json.dumps(FormatMessageTests._raw_alarm("OK_TO_FIRING", "FIRING")))

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(published, ["https://ntfy.example.com/secret-topic"])

    def test_publish_error_log_redacts_topic(self):
        def failing_post(url):
            raise RuntimeError(f"404 Client Error: Not Found for url: {url}")

        with self.assertLogs("ntfy-relay", level="ERROR") as logs:
            result, _ = self._invoke(
                json.dumps(FormatMessageTests._raw_alarm("OK_TO_FIRING", "FIRING")),
                post=failing_post,
            )

        self.assertEqual(result["status_code"], 500)
        joined = "\n".join(logs.output)
        self.assertNotIn("secret-topic", joined)
        self.assertIn("<redacted>", joined)


if __name__ == "__main__":
    unittest.main()
