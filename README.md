# OCI Notifications to ntfy Relay

This sample shows how to relay Oracle Cloud Infrastructure (OCI) Notifications
messages to an ntfy topic by using an OCI Function.

The intended path is:

```text
OCI Alarm -> OCI Notifications Topic -> OCI Function -> ntfy topic
```

This relay is intentionally small:

- OCI Monitoring Alarm continues to own state changes and deduplication.
- OCI Notifications continues to own fan-out.
- The function only adapts the OCI Notifications payload into an ntfy publish
  request.

## Why use a relay function?

If you want to keep ntfy clients on a random topic with anonymous read access,
OCI's direct `CUSTOM_HTTPS` notification subscription model is awkward because
it expects an authenticated HTTPS endpoint with its own confirmation flow.

Using an OCI Function keeps the alert state machine inside OCI while avoiding a
separate external webhook relay service.

## Prerequisites

Before you deploy this sample, make sure you have:

- an OCI tenancy with Oracle Functions enabled
- an OCI Notifications topic
- an OCI Vault
- an ntfy server reachable from OCI Functions
- a topic secret stored in OCI Vault
- a publish token secret stored in OCI Vault

This sample assumes the following Vault secret names by default:

- `ntfy-alert-topic`
- `ntfy-function-relay-token`

You can change the names by overriding the function config values below.

## Function config

Set these function configuration keys:

- `NTFY_HOST`
- `OCI_VAULT_ID`
- `NTFY_TOPIC_SECRET_NAME`
- `NTFY_TOKEN_SECRET_NAME`

Example:

```bash
fn config function <app-name> oci-notifications-ntfy-relay NTFY_HOST ntfy.example.com
fn config function <app-name> oci-notifications-ntfy-relay OCI_VAULT_ID <vault-ocid>
fn config function <app-name> oci-notifications-ntfy-relay NTFY_TOPIC_SECRET_NAME ntfy-alert-topic
fn config function <app-name> oci-notifications-ntfy-relay NTFY_TOKEN_SECRET_NAME ntfy-function-relay-token
```

## IAM

The function resource principal needs permission to read the two Vault secrets.
For a function-specific dynamic group, the policy shape is:

```text
Allow service FaaS to use virtual-network-family in compartment id <compartment-ocid>
Allow service FaaS to read repos in tenancy
Allow dynamic-group <functions-dynamic-group> to read secret-bundles in compartment id <compartment-ocid> where all {target.secret.name='ntfy-alert-topic'}
Allow dynamic-group <functions-dynamic-group> to read secret-bundles in compartment id <compartment-ocid> where all {target.secret.name='ntfy-function-relay-token'}
```

## Deploy

Deploy with the standard Oracle Functions workflow:

```bash
fn -v deploy --app <app-name>
```

## Subscribe OCI Notifications to the function

Create an OCI Notifications subscription on your topic with:

- protocol: `ORACLE_FUNCTIONS`
- endpoint: this function

Once connected, OCI Alarm notifications published into the topic will invoke
the function, which will then publish to your ntfy topic.

## ntfy expectations

The function publishes to:

```text
https://<NTFY_HOST>/<topic>
```

It uses:

- `Authorization: Bearer <token>`
- `Title: ...`
- `Tags: ...`

The token therefore needs write access to the target topic.

## Payload behavior

The function is written to work with standard OCI Notifications message bodies,
including alarm notifications routed through OCI Notifications.

It attempts to surface:

- title / alarm display name
- severity
- lifecycle state
- region
- timestamp
- summary/body

If the payload contains non-Latin-1 title text, the message body preserves the
full Unicode value while the HTTP `Title` header is downgraded to a header-safe
variant.

## Scope

This sample is not:

- a custom alert state machine
- a replacement for OCI Alarm deduplication
- a full ntfy deployment stack
- a Terraform, Argo CD, or Kubernetes reference implementation

It is only the minimal relay needed to bridge OCI Notifications into ntfy.
