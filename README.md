# OCI Notifications to ntfy Relay

An [OCI Function](https://docs.oracle.com/en-us/iaas/Content/Functions/home.htm)
that turns Oracle Cloud Infrastructure notifications and a few common webhooks
into short, readable [ntfy](https://ntfy.sh) push messages.

```text
OCI Alarm / OSMH event / Cloud Guard event -> OCI Notifications topic -> function -> ntfy
HCP Terraform notification / Alertmanager  -> OCI API Gateway        -> function -> ntfy
```

The relay only formats and forwards. OCI Monitoring keeps owning alarm state
and deduplication, OCI Notifications keeps owning fan-out, and Alertmanager
keeps owning grouping.

## Features

| Source | How it arrives | What the relay does |
|---|---|---|
| OCI Monitoring alarms | Notifications subscription (`ORACLE_FUNCTIONS`) | Parses the [Alarm Message Format](https://docs.oracle.com/en-us/iaas/Content/Monitoring/alarm-message-format.htm): state from `type`, plain-text `body`, `alarmMetaData[].alarmUrl` as the click link. `FIRING_TO_OK` is a recovery, `RESET` stays a warning. |
| OS Management Hub events | Notifications subscription | Summarises the managed instance: pending updates, security errata, reboot flag. |
| Cloud Guard problem events | Notifications subscription | Shows risk level, problem, resource and recommendation. |
| HCP Terraform notifications | API Gateway route | Verifies `X-TFE-Notification-Signature` (HMAC-SHA512) and shows workspace, run status and links. |
| Alertmanager webhooks | API Gateway route ending in `/alertmanager` | Verifies a bearer token and shows status, alert name, scope and runbook. |

Each message sets the ntfy `Title`, `Tags`, `Priority` and, when there is a
next hop, `Click` header. The link is also kept in the body.

## Security model

- A request that reaches the function through API Gateway (the Fn FDK sees
  `Fn-Http-Request-Url`, which only HTTP-triggered invocations carry) must
  authenticate: the `/alertmanager` route needs the bearer token, every other
  gateway route needs a valid HCP Terraform signature. Anything else gets
  `401` and nothing is published.
- Only direct invocations from OCI Notifications (no `Fn-Http-Request-Url`)
  reach the OCI alarm, OSMH and Cloud Guard formatters.
- Every secret comes from OCI Vault through the function's resource principal.
- Error logs carry no traceback, and Vault values in exception text are
  replaced with `<redacted>`.

## Configuration

Function configuration keys:

| Key | Required | Meaning |
|---|---|---|
| `NTFY_HOST` | yes | ntfy server host name; the relay posts to `https://<NTFY_HOST>/<topic>`. |
| `OCI_VAULT_ID` | yes | OCID of the Vault that holds the secrets below. |
| `NTFY_TOPIC_SECRET_NAME` | yes | Vault secret holding the ntfy topic. |
| `NTFY_TOKEN_SECRET_NAME` | yes | Vault secret holding an ntfy token with write access to the topic. |
| `HCP_TERRAFORM_NOTIFICATION_SECRET_NAME` | for HCP Terraform | Vault secret holding the notification HMAC token. |
| `ALERTMANAGER_WEBHOOK_TOKEN_SECRET_NAME` | for Alertmanager | Vault secret holding the bearer token Alertmanager sends. |
| `NTFY_CLOUDFLARE_ACCESS_CLIENT_ID_SECRET_NAME`, `NTFY_CLOUDFLARE_ACCESS_CLIENT_SECRET_SECRET_NAME` | optional, together | Vault secrets for a Cloudflare Access service token in front of ntfy. |
| `LOG_LEVEL` | optional | `INFO` (default) or `DEBUG`. |

## Deploy

### 1. Get the image into your OCI Container Registry

OCI Functions only runs images from Container Registry in the function's own
region; creating a function from a GHCR image is rejected with
`The image must be an OCIR image in this region's registry`. Release images are
multi-architecture (`linux/amd64`, `linux/arm64`), so they work for
`GENERIC_X86`, `GENERIC_ARM` and `GENERIC_X86_ARM` application shapes. On
`GENERIC_X86_ARM` OCI Functions chooses the architecture per container by
capacity; every structured log line carries an `architecture` field
(`x86_64` or `aarch64`) so you can confirm the function runs on both, as
[Oracle recommends](https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsspecifyingcomputearchitectures.htm).
CI builds and imports the function on a native `ubuntu-24.04` and
`ubuntu-24.04-arm` runner, and the release workflow runs the pushed digest on
both before attesting it, so an attested release has started on both
architectures. To check the OCI Functions runtime itself, create the same
image in a `GENERIC_X86` and a `GENERIC_ARM` application as well.

Verify the release image, then copy it by digest:

```bash
IMAGE=ghcr.io/ryan02i5-labs/oci-notifications-ntfy-relay
DIGEST=sha256:...   # from the release notes or the release workflow summary
TAG=v1.0.0

gh attestation verify "oci://${IMAGE}@${DIGEST}" \
  --repo Ryan02I5-Labs/oci-notifications-ntfy-relay \
  --signer-workflow Ryan02I5-Labs/oci-notifications-ntfy-relay/.github/workflows/release.yml \
  --source-ref "refs/tags/${TAG}" \
  --deny-self-hosted-runners

docker login <region-key>.ocir.io
docker buildx imagetools create \
  --tag "<region-key>.ocir.io/<namespace>/<repository>:${TAG}" \
  "${IMAGE}@${DIGEST}"
docker buildx imagetools inspect "<region-key>.ocir.io/<namespace>/<repository>:${TAG}"
```

`imagetools create` copies an image index as is
([Docker docs](https://docs.docker.com/reference/cli/docker/buildx/imagetools/create/));
check that the digest it reports equals `DIGEST`.

You can also build the image yourself from this repository with
`docker buildx build` or `fn build`.

### 2. Create the function

Create it from the OCIR image with the
[Console, CLI or Terraform](https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionscreatingfunction-task.htm),
for example:

```bash
fn create function <app-name> oci-notifications-ntfy-relay \
  <region-key>.ocir.io/<namespace>/<repository>:v1.0.0
fn config function <app-name> oci-notifications-ntfy-relay NTFY_HOST ntfy.example.com
fn config function <app-name> oci-notifications-ntfy-relay OCI_VAULT_ID <vault-ocid>
fn config function <app-name> oci-notifications-ntfy-relay NTFY_TOPIC_SECRET_NAME ntfy-alert-topic
fn config function <app-name> oci-notifications-ntfy-relay NTFY_TOKEN_SECRET_NAME ntfy-function-relay-token
```

128 MB of memory and a 30 second timeout are enough.

### 3. IAM

Create a dynamic group for the function
(`ALL {resource.type = 'fnfunc', resource.id = '<function-ocid>'}`) and grant:

```text
Allow service FaaS to use virtual-network-family in compartment id <compartment-ocid>
Allow service FaaS to read repos in tenancy
Allow dynamic-group <function-group> to read secret-bundles in compartment id <compartment-ocid> where all {target.secret.name='ntfy-alert-topic'}
Allow dynamic-group <function-group> to read secret-bundles in compartment id <compartment-ocid> where all {target.secret.name='ntfy-function-relay-token'}
```

Add one `read secret-bundles` statement per optional secret you configure. For
richer OS Management Hub messages, also allow:

```text
Allow dynamic-group <function-group> to read osmh-family in compartment id <compartment-ocid>
```

If you use API Gateway, give the gateway's dynamic group
(`ALL {resource.type = 'apigateway', resource.id = '<gateway-ocid>'}`)
`use functions-family`, as in
[Adding a Function as an API Gateway Back End](https://docs.oracle.com/en-us/iaas/Content/APIGateway/Tasks/apigatewayusingfunctionsbackend.htm).

### 4. Connect the sources

- **OCI Notifications:** add a subscription with protocol `ORACLE_FUNCTIONS`
  and this function as the endpoint. Alarms, OS Management Hub events and
  Cloud Guard events published to the topic invoke the function directly.
- **HCP Terraform:** create an API Gateway deployment with a `POST` route whose
  back end is this function, and use the route URL as a generic webhook
  notification with an HMAC token equal to the Vault secret.
- **Alertmanager:** add a `POST` route ending in `/alertmanager` and configure a
  webhook receiver with `http_config.authorization.credentials` set to the
  bearer token stored in Vault.

## Releases and verification

Publishing a GitHub Release `vX.Y.Z` runs `.github/workflows/release.yml` on
GitHub-hosted runners. It runs the tests, pushes
`ghcr.io/ryan02i5-labs/oci-notifications-ntfy-relay:X.Y.Z` (and `X.Y`), and
attests the build provenance with
[artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
BuildKit also attaches its own provenance and an SBOM to the image index.
Deploy by digest, not by tag.

## Development

```bash
python3 -m unittest discover -s . -p 'test_func.py' -v
docker buildx build --platform linux/amd64,linux/arm64 .
```

Dependencies and base images are pinned and updated by Dependabot.

## Related

- The ntfy [integrations list](https://docs.ntfy.sh/integrations/) links here.
- A minimal version of this relay is proposed as an Oracle sample in
  [oracle-samples/oracle-functions-samples#73](https://github.com/oracle-samples/oracle-functions-samples/pull/73).

## License

[Universal Permissive License v1.0](LICENSE.txt).
