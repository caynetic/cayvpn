# Edit an existing connection

Open **Overview → Edit connection** for a device. Choose **Standard protection**
or **Block ads and trackers**, and **Smart IPv6** or **Require IPv6**, then save.
The operation requires the same recent owner approval as changing a Location.

CayVPN preserves the device's identity, keys, addresses, protocol, and currently
selected Location or backup group. Saving a changed setting briefly resets that
device's connections. Saving unchanged settings does not reset its connection.

DNS changes create a new configuration revision. Download and import that
configuration into the VPN app, replacing its previous imported profile, then
mark the current configuration imported. Older open confirmation pages cannot
confirm a newer revision. An IPv6-only change takes effect on the server after
verification and does not require importing a new profile.

Require IPv6 is accepted only when the currently selected Location has passed
both IPv4 and IPv6 checks and the client has an IPv6 address. The edit does not
silently switch to another pool member. If the current Location is IPv4-only,
choose a verified IPv6-ready Location before enabling Require IPv6.

If applying the change fails, CayVPN attempts to restore the previous settings
and verified route. If recovery cannot be verified, the connection stays
blocked. A DNS rollback creates another configuration revision because the
pending profile may already have been downloaded. If the agent's response is
lost, the desired settings remain pending for the existing worker recovery
flow; the UI does not report them as applied. Another edit is refused while
that change is pending. Stale settings forms must be reloaded.

## Owner API

Read `GET /api/v1/clients` to obtain the client's `settings_revision`. Submit:

```http
POST /api/v1/clients/123/settings
Content-Type: application/json
Idempotency-Key: a-unique-request-key-at-least-16-characters
X-CSRFToken: the-current-session-csrf-token
```

```json
{
  "dns_mode": "ad_blocking",
  "ipv6_policy": "required",
  "settings_revision": "the-value-from-the-current-client-response"
}
```

Both settings are required; other fields are rejected. Use the authenticated
owner session and normal recent owner approval. `dns_mode` accepts `standard`
or `ad_blocking`; `ipv6_policy` accepts `auto` or `required`.

The response includes the operation ID, agent status/result, updated client,
and route state. HTTP 200 means verified or unchanged, 202 means pending agent
recovery, and 409 means a conflict or unverified/failed change. Invalid request
shapes use 400. Replaying an identical request with its original idempotency key
returns the original receipt; read the client again for its latest state.

`configuration_update_available` compares generated and confirmed configuration
revisions. Post `installed=on` and the displayed `config_version` to the existing
`/clients/<id>/config/confirm` form endpoint only after importing that revision.
