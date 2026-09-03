# Code Architecture Reference

Complete reference for the codebase after comment removal.

## Package Structure

### cmd/proxywatch (Entry Point)
Main application entry point with multiple operation modes:

| Function | Purpose |
|----------|---------|
| main | Entry point - parses flags, initializes modes |
| defaultUIRoleFilter | Returns default role filter map |
| isStdinTTY | Checks if running in terminal (vs headless) |
| bootstrapKeystore | Loads keystore values at startup |
| bootstrapRuntimeConfig | Loads runtime configuration |
| buildServiceArgs | Builds Windows service arguments |
| configureDetectionOutputsFromRuntime | Configures detection output paths |
| runContourMode | Runs headless tunnel server/client |
| parsePorts | Parses comma-separated port string |

**CLI Flags:**
- `-connect`: Agent mode - stream to remote server
- `-listen`: Server mode - accept agent connections
- `-service`: Windows service mode
- `-contour-server/client`: Tunnel mode
- `-debug-api`: HTTP debug endpoint
- `-training-export`: ML training data export

---

### internal/agent (Remote Agent System)

#### auth/ (Authentication)
| File | Purpose |
|------|---------|
| auth.go | Token validation and authentication |
| bootstrap.go | Initial agent enrollment |
| codec.go | Token encoding/decoding |
| enroll.go | Server enrollment protocol |
| tls.go | TLS certificate handling |
| trust.go | Trust chain verification |

#### pb/ (Protocol Buffers)
| File | Purpose |
|------|---------|
| types.go | Message type definitions |
| service.go | gRPC service definitions |

#### Core Files
| File | Purpose |
|------|---------|
| client.go | Agent client - connects to server, streams data |
| server.go | Agent server - accepts connections, aggregates data |
| convert.go | Converts between internal and protobuf types |
| debug.go | Debug API for agent introspection |

---

### internal/detection (Detection Engine)

#### Main Files
| File | Original | Purpose |
|------|----------|---------|
| orchestrator.go | Orchestrator | Coordinates detection pipeline |
| classifier.go | Classify | Main classification entry point |
| incremental.go | - | Incremental state updates |
| wrappers.go | - | Wrapper utilities |
| display.go | - | Display formatting |

#### behavior/ (Behavior Analysis)
| File | Purpose |
|------|---------|
| beacon.go | Detect beaconing patterns (C2) |
| cdn.go | CDN traffic identification |
| distinguish.go | Distinguish traffic types |
| helpers.go | Helper functions |
| ipc.go | Inter-process communication |
| listener.go | Listener detection |
| outbound.go | Outbound connection analysis |
| pivot.go | Lateral movement detection |
| saas.go | SaaS traffic identification |
| session.go | Session tracking |
| ssh_baseline.go | SSH baseline behavior |

#### features/ (ML Feature Extraction)
| File | Purpose |
|------|---------|
| extract.go | Extract features from candidates |
| schema.go | Feature vector schema |
| beacon.go | Beacon-specific features |
| listener_features.go | Listener features |
| outbound_features.go | Outbound features |
| pivot.go | Pivot features |
| session.go | Session features |

#### gbdt/ (Gradient Boosted Decision Trees)
| File | Purpose |
|------|---------|
| trainer.go | Model training logic |
| tree.go | Decision tree implementation |
| dataset.go | Training data management |
| evaluate.go | Model evaluation |
| export.go | Export training data |
| validation.go | Cross-validation |
| errors.go | Error definitions |
| training_schema.go | Training record schema |

#### ml/ (Machine Learning)
| File | Purpose |
|------|---------|
| predictor.go | Model prediction interface |
| native.go | Native Go model implementation |
| buffer.go | Training data buffer |
| retrain.go | Continuous retraining |
| metrics.go | Model metrics |

#### model/ (Detection Model)
| File | Purpose |
|------|---------|
| model.go | Core model state |
| analyze.go | Analysis functions |
| decide.go | Decision logic |
| egress.go | Egress detection |
| experience.go | Historical experience |
| feedback.go | User feedback handling |
| maturity.go | Process maturity scoring |
| patterns.go | Pattern matching |
| quality.go | Quality metrics |
| runtime.go | Runtime state |

#### output/ (Output Formatters)
| File | Purpose |
|------|---------|
| output.go | Output coordination |
| debug_api.go | Debug HTTP API |
| siem_api.go | SIEM export and rule generation |
| suricata.go | Suricata rule generation |
| timeline.go | Candidate state timeline |
| yara.go | YARA rule generation |

---

### internal/alerts (Webhook Alerting)
| File | Purpose |
|------|---------|
| webhook.go | Outbound webhook alerts for malicious candidates |

---

### internal/pcap (PCAP Analysis)
| File | Purpose |
|------|---------|
| ingest.go | PCAP file ingestion |
| tail.go | Live PCAP tailing |
| beacon_analysis.go | Beacon pattern detection from traffic |
| beacon_signals.go | Beacon signal extraction |
| cross_candidate.go | Cross-candidate correlation |
| dns_enrich.go | DNS enrichment |
| dns_parse.go | DNS packet parsing |
| http_enrich.go | HTTP enrichment |
| http_parse.go | HTTP packet parsing |
| http_signatures.go | HTTP-based signatures |
| ssh_banner.go | SSH banner analysis |
| ssh_enrich.go | SSH enrichment |
| tls_enrich.go | TLS enrichment |
| tls_parse.go | TLS packet parsing |
| tls_database.go | Known TLS fingerprints |
| zeek.go | Zeek log integration |
| apply_labels.go | Label application |
| rare_signatures.go | Rare signature detection |

#### scoring/ (Scoring Engine)
| File | Purpose |
|------|---------|
| rank.go | Ranking candidates |
| behavior.go | Behavior scoring |
| network.go | Network scoring |
| roles.go | Role assignment |
| child_tunnel.go | Child tunnel scoring |
| delegated.go | Delegated scoring |
| history.go | Historical scoring |
| util.go | Utility functions |

#### telemetry/ (System Telemetry)
| File | Purpose |
|------|---------|
| network_linux.go | Linux network collection |
| network_darwin.go | macOS network collection |
| network_windows.go | Windows network collection |
| network_capture_common.go | Common capture code |
| process_linux.go | Linux process collection |
| process_darwin.go | macOS process collection |
| process_windows.go | Windows process collection |
| process_windows_libs.go | Windows library detection |
| windows_syscalls.go | Windows syscall wrappers |
| telemetry_stub.go | Stub for unsupported platforms |

---

### internal/contour (Tunnel System)

#### Main Files
| File | Purpose |
|------|---------|
| contour.go | Main tunnel coordinator |
| reexport.go | Re-exported types |

#### api/ (HTTP API)
| File | Purpose |
|------|---------|
| api.go | Tunnel control API |

#### probe/ (Protocol Probing)
| File | Purpose |
|------|---------|
| probe.go | Main probe coordinator |
| probe_config.go | Probe configuration |
| probe_endpoints.go | Endpoint probing |
| probe_findings.go | Probe findings |
| probe_packet_wire.go | Packet construction |
| probe_roundtrip.go | Round-trip testing |
| probe_services.go | Service probing |
| probe_transport.go | Transport layer |
| shared.go | Shared utilities |

#### tunnel/ (Tunnel Implementation)
| File | Purpose |
|------|---------|
| tunnel.go | Core tunnel logic |
| tunnel_deaddrop.go | Dead drop protocol |
| tunnel_protocols.go | Protocol handlers |
| tunnel_protocols_api.go | Protocol API |
| tunnel_protocols_ext.go | Extended protocols |
| tunnel_services.go | Tunnel services |

---

### internal/keystore (Secure Storage)
| File | Purpose |
|------|---------|
| keystore.go | Main keystore interface |
| keystore_crypto.go | Encryption/decryption |
| keystore_runtime.go | Runtime value access |
| keystore_vault.go | Vault integration |

---

### internal/proxyhound (Data Collection)
| File | Purpose |
|------|---------|
| collect.go | Collect system data |
| upload.go | Upload to server |

---

### internal/safeio (Safe I/O)
| File | Purpose |
|------|---------|
| safeio.go | Safe file operations |

---

### internal/shared (Shared Types)
| File | Purpose |
|------|---------|
| app.go | Application state |
| asn.go | ASN lookup |
| candidate.go | Detection candidate |
| classify.go | Classification helpers |
| display.go | Display utilities |
| distinguishing.go | Traffic distinguishing |
| dns_cache.go | DNS caching |
| eventlog.go | Event logging |
| exe_hash.go | Executable hashing |
| fp_post_classify.go | Post-classification FP filtering |
| heuristics.go | Detection heuristics |
| inspector_conn_history.go | Connection history for inspector |
| linger.go | Candidate lingering |
| online_evidence.go | Online evidence collection |
| operator_labels.go | Operator-defined labels |
| pcap_mode.go | PCAP mode state |
| pcap_operator_labels.go | PCAP operator labels |
| pcap_tls_labels.go | PCAP TLS labels |
| proto_probe.go | Protocol probing |
| proto_services.go | Protocol service definitions |
| publisher_domains.go | Publisher domain lists |
| roles.go | Role definitions |
| session_log.go | Session logging |
| signature.go | Code signing |
| signature_darwin.go | macOS signing |
| signature_unix.go | Unix signing |
| signature_windows.go | Windows signing |
| signature_worker.go | Background verification |
| state.go | Global state |
| stats.go | Statistics tracking |
| vendor_fp_shape.go | Vendor FP shape evaluation |
| verifier_pkg_*.go | Package verification |
| verifier_publisher_dns.go | Publisher DNS verification |
| whitelist.go | Whitelist management |

---

### internal/ui (Terminal UI)

#### Main Files
| File | Purpose |
|------|---------|
| loop.go | Main UI loop |
| root.go | Root UI component |

#### common/ (Shared UI)
| File | Purpose |
|------|---------|
| styles.go | UI styles |
| helpers.go | Helper functions |
| render.go | Rendering utilities |

#### keys/ (Key Handlers)
| File | Purpose |
|------|---------|
| dashboard.go | Dashboard key handling |
| collect.go | Collection key handling |
| contour.go | Contour key handling |
| keystore.go | Keystore key handling |
| shared.go | Shared key handling |
| siem.go | SIEM key handling |
| training.go | Training key handling |
| workflow.go | Workflow key handling |

#### platform/ (Platform-Specific)
| File | Purpose |
|------|---------|
| icons_unix.go | Unix icons |
| icons_windows.go | Windows icons |
| program_unix.go | Unix program handling |
| program_windows.go | Windows program handling |
| root_unix.go | Unix root detection |
| root_windows.go | Windows admin detection |

#### render/ (Renderers)
| File | Purpose |
|------|---------|
| dashboard.go | Dashboard rendering |
| collect.go | Collection rendering |
| contour.go | Contour rendering |
| keystore.go | Keystore rendering |
| whitelist.go | Whitelist rendering |
| common_bridge.go | Common bridge |
| consts.go | Constants |
| helpers.go | Helper functions |

#### views/ (View Components)
| File | Purpose |
|------|---------|
| dashboard.go | Main dashboard view |
| bridge.go | Bridge view |
| contour.go | Contour view |
| inspector.go | Inspector view |
| keystore.go | Keystore view |
| legacy.go | Legacy view |
| live.go | Live view |
| proxyhound.go | Proxyhound view |
| report.go | Report view |
| siem.go | SIEM view |
| training.go | Training view |
| whitelist.go | Whitelist view |

---

## Key Data Structures

### Candidate (internal/shared/candidate.go)
The core detection unit representing a process with network activity.

| Field | Type | Purpose |
|-------|------|---------|
| Host | string | Host identifier |
| Proc | *ProcessInfo | Process information |
| Conns | []ConnectionInfo | Network connections |
| Listeners | []ListenerInfo | TCP listeners |
| UDPListeners | []UDPListenerInfo | UDP listeners |
| Role | string | Assigned role |
| ControlSubtype | string | Subtype qualifier |
| SuggestedRole | string | Topology suggested role |
| Score | int | Confidence score |
| Confidence | int | Confidence level |
| Signals | []string | Detection signals |
| Reasons | []string | Score reasons |
| MLRole | string | ML-predicted role |
| MLConfidence | float64 | ML confidence |
| MLActive | bool | ML is active |
| BeaconIntervalMs | int | Beacon interval |
| BeaconJitter | float64 | Beacon jitter |
| StrongEvidence | bool | Has strong evidence |
| TrafficVerified | bool | Traffic verified |
| ActiveProxying | bool | Active relay detected |
| DelegatedEgress | bool | Traffic via another process |
| RawSocket | bool | Has raw sockets |

### AppState (internal/shared/app.go)
Global application state passed through the UI.

### ProcessInfo (internal/shared/candidate.go)
Process metadata including PID, name, path, user, SHA256, signature trust.

### ConnectionInfo (internal/shared/candidate.go)
Network connection details including local/remote addresses, ports, state, protocol.

---

## Detection Roles

| Role | Description |
|------|-------------|
| c2-beacon | Command & control beaconing |
| c2-shell | Interactive C2 shell |
| tunnel-child | Tunnel child process |
| tunnel-forward | Forward tunnel |
| tunnel-reverse | Reverse tunnel |
| pivot | Lateral movement |
| listener | Network listener |
| exfil | Data exfiltration |
| outbound | Standard outbound connection |

---

## Configuration Files

| Path | Purpose |
|------|---------|
| ~/.proxywatch/keystore.json | Encrypted settings |
| ~/.proxywatch/whitelist.json | Whitelisted processes |
| ~/.proxywatch/memory.json | Classifier memory |
| ~/.proxywatch/models/ | ML models |
| ~/.proxywatch/collections/ | Collected data |

---

## Building

```bash
# All platforms
GOOS=linux go build ./cmd/proxywatch
GOOS=darwin go build ./cmd/proxywatch
GOOS=windows go build ./cmd/proxywatch
```
