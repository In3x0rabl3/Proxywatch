# Microsoft Sentinel output

ProxyWatch can send detection lifecycle events to Microsoft Sentinel through the
Azure Monitor Logs Ingestion API. The output uses a flat, typed record per
detection so the DCR can map directly to a custom Log Analytics table. Signals,
reasons, connections, and listeners are `dynamic` columns.

The sender emits:

- `DetectionCreated` when a candidate first meets the configured minimum score.
- `DetectionUpdated` when its role, state, evidence, connection shape, or score/confidence band changes.
- `DetectionResolved` when it disappears or no longer meets the minimum score.

`EntityId` is stable across role changes and is the recommended correlation
key. Uploads run outside the classifier loop, use the Azure SDK's retry policy,
and are split below the Logs Ingestion API's 1 MB request limit.

A complete three-record sample suitable for the Azure custom-table/DCR creation
workflow is available at
[`docs/samples/proxywatch-sentinel-events.json`](samples/proxywatch-sentinel-events.json).
It contains created, updated, and resolved events and populates every column.

## Configuration

The DCE endpoint, DCR immutable ID, and stream name are always required:

```sh
export PROXYWATCH_SENTINEL_DCE_ENDPOINT='https://proxywatch-dce.westus2-1.ingest.monitor.azure.com'
export PROXYWATCH_SENTINEL_DCR_ID='dcr-00000000000000000000000000000000'
export PROXYWATCH_SENTINEL_STREAM_NAME='Custom-ProxywatchDetections_CL'
```

The endpoint can also be a direct DCR logs-ingestion endpoint. Do not use the
DCR Azure resource ID for `PROXYWATCH_SENTINEL_DCR_ID`; use its `immutableId`
value, which starts with `dcr-`.

### Managed identity

Managed identity is the default authentication mode:

```sh
export PROXYWATCH_SENTINEL_AUTH='managed_identity'
```

No credential values are required for a system-assigned identity. To select a
user-assigned identity, also set its client ID:

```sh
export AZURE_CLIENT_ID='00000000-0000-0000-0000-000000000000'
```

### Application ID and secret

```sh
export PROXYWATCH_SENTINEL_AUTH='client_secret'
export AZURE_TENANT_ID='00000000-0000-0000-0000-000000000000'
export AZURE_CLIENT_ID='00000000-0000-0000-0000-000000000000'
export AZURE_CLIENT_SECRET='replace-with-secret'
```

These values can also be stored in the ProxyWatch keystore. The identity—either
the managed identity or service principal—must have the **Monitoring Metrics
Publisher** role on the DCR resource. Role propagation can take several minutes.

## DCR input stream

Create a custom table named `ProxywatchDetections_CL`, then use the following
input stream declaration in the DCR. The configured stream name must exactly
match the `Custom-ProxywatchDetections_CL` key.

```json
{
  "streamDeclarations": {
    "Custom-ProxywatchDetections_CL": {
      "columns": [
        { "name": "TimeGenerated", "type": "datetime" },
        { "name": "SchemaVersion", "type": "string" },
        { "name": "EventType", "type": "string" },
        { "name": "EntityId", "type": "string" },
        { "name": "DetectionId", "type": "string" },
        { "name": "Cycle", "type": "long" },
        { "name": "Host", "type": "string" },
        { "name": "ProcessId", "type": "long" },
        { "name": "ProcessName", "type": "string" },
        { "name": "ProcessPath", "type": "string" },
        { "name": "User", "type": "string" },
        { "name": "Role", "type": "string" },
        { "name": "RoleFamily", "type": "string" },
        { "name": "State", "type": "string" },
        { "name": "Score", "type": "long" },
        { "name": "Confidence", "type": "long" },
        { "name": "StrongEvidence", "type": "boolean" },
        { "name": "ActiveProxying", "type": "boolean" },
        { "name": "TrafficVerified", "type": "boolean" },
        { "name": "InboundTotal", "type": "long" },
        { "name": "OutboundTotal", "type": "long" },
        { "name": "OutboundExternal", "type": "long" },
        { "name": "OutboundInternal", "type": "long" },
        { "name": "OutboundLoopback", "type": "long" },
        { "name": "TcpListenerCount", "type": "long" },
        { "name": "UdpListenerCount", "type": "long" },
        { "name": "ControlDurationSeconds", "type": "long" },
        { "name": "ControlRemoteAddress", "type": "string" },
        { "name": "ControlRemotePort", "type": "long" },
        { "name": "Signals", "type": "dynamic" },
        { "name": "Reasons", "type": "dynamic" },
        { "name": "Connections", "type": "dynamic" },
        { "name": "TcpListeners", "type": "dynamic" },
        { "name": "UdpListeners", "type": "dynamic" }
      ]
    }
  }
}
```

Use `source` as the DCR transformation when the destination table has the same
schema. A typical data flow is:

```json
{
  "streams": ["Custom-ProxywatchDetections_CL"],
  "destinations": ["<log-analytics-destination-name>"],
  "transformKql": "source",
  "outputStream": "Custom-ProxywatchDetections_CL"
}
```

## Useful KQL

Current unresolved detections:

```kusto
ProxywatchDetections_CL
| summarize arg_max(TimeGenerated, *) by EntityId
| where EventType != "DetectionResolved"
| project TimeGenerated, Host, ProcessName, ProcessId, Role, State, Score, Signals
```

Pivot activity:

```kusto
ProxywatchDetections_CL
| where Role == "control-pivot" or set_has_element(Signals, "pivot-non-loopback-internal")
| project TimeGenerated, EventType, Host, ProcessName, ProcessId,
          ControlRemoteAddress, ControlRemotePort, Connections, Reasons
```
