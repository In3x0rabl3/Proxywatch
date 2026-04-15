// Package features extracts behavioral feature vectors from ProxyWatch
// candidates for ML-based role classification.
//
// 120 features organized by role: each feature belongs to exactly one role.
// Each role has a balanced mix of host-based (H) and network-based (N) features.
package features

// MaxFeatures is the total number of features in the vector.
//
// Schema-bump history: 120 -> 122 added FOnlineKnownBenign/Malicious for
// Authenticode online verification. Models trained against the old schema
// are invalidated and the continuous learner retrains from its buffer.
const MaxFeatures = 122

// FeatureVector is the normalized input to the ML model.
// Field order matches the feature schema.
type FeatureVector struct {
	Values [MaxFeatures]float64
	Valid  bool
}

// FeatureNames returns all feature names in order.
func FeatureNames() []string {
	out := make([]string, len(featureNames))
	copy(out, featureNames[:])
	return out
}

// ToMap converts a FeatureVector to a name→value map for export.
func (fv FeatureVector) ToMap() map[string]float64 {
	m := make(map[string]float64, MaxFeatures)
	for i := 0; i < MaxFeatures; i++ {
		m[featureNames[i]] = fv.Values[i]
	}
	return m
}

// ── Role 1: Control-Beacon (0-23) — 12 network + 12 host ──────────────
const (
	FBeaconIntervalMsConfirmed = iota // (N) callback interval in ms
	FBeaconJitterCoV                  // (N) jitter coefficient of variation
	FBeaconSynCycleCount              // (N) SYN cycling events
	FBeaconCallbackSuccessRate        // (N) ESTABLISHED / SYN attempts
	FBeaconTargetStability            // (N) target IP consistency
	FBeaconPortConsistency            // (N) always same dest port
	FBeaconSSLLikely                  // (N) uses 443/8443
	FBeaconMultiTarget                // (N) failover across IPs
	FBeaconConnPerBurst               // (N) connections per cycle
	FBeaconDriftRate                  // (N) interval trend over time
	FBeaconIntervalAutocorr           // (N) periodicity strength
	FBeaconHitsCount                  // (N) total confirmed beacon bursts
	FBeaconIOPerSecondAvg             // (H) total IO / process age
	FBeaconIOReadRatio                // (H) read/(read+write)
	FBeaconPayloadSizeMean            // (H) avg bytes per burst
	FBeaconSleepRegularity            // (H) silence period consistency
	FBeaconBurstSilenceShape          // (H) burst-to-silence ratio
	FBeaconCPUToAgeRatio              // (H) CPU seconds / process age
	FBeaconMemoryVariance             // (H) working set variance
	FBeaconChildCount                 // (H) child processes spawned
	FBeaconHasCryptoLib               // (H) loaded crypto/TLS library
	FBeaconJitterEntropy              // (H) entropy of interval differences
	FBeaconLongInterval               // (H) interval >5min flag
	FBeaconIOZeroPeriods              // (H) observation cycles with zero IO
)

// ── Role 2: Control-Session (24-47) — 11 network + 13 host ────────────
const (
	FSessionControlDurationSec = iota + 24 // (N) control channel hold time
	FSessionConnLifetimeMaxSec             // (N) longest single connection
	FSessionDistinctTargets                // (N) unique targets
	FSessionExternalConnCount              // (N) external connections
	FSessionConnChurnRate                  // (N) connections per minute
	FSessionIOWriteRatio                   // (N) write/(read+write)
	FSessionASNMismatch                    // (N) vendor/ASN alignment flag
	FSessionPreExisting                    // (N) had connections on first observation
	FSessionControlChannelAgeSec           // (N) oldest ESTABLISHED age
	FSessionInternalConnCount              // (N) internal connections
	FSessionIOCurrentRate                  // (N) instantaneous IO rate
	FSessionIORWBalance                    // (H) read/write ratio
	FSessionIOBurstiness                   // (H) stddev of IO rate / mean
	FSessionIntegrityLevel                 // (H) 0=low, 1=med, 2=high, 3=system
	FSessionCmdLength                      // (H) command line length
	FSessionCmdHasEncoded                  // (H) encoded content flag
	FSessionChildProcessCount              // (H) children spawned
	FSessionChildIsLOLBin                  // (H) children are system binaries
	FSessionDelegatedEgressStrong           // (H) delegated egress flag
	FSessionParentScore                    // (H) parent detection score
	FSessionRareParent                     // (H) rare parent-child combo flag
	FSessionCPUToIORatio                   // (H) CPU per MB IO
	FSessionIOOtherRatio                   // (H) IOOther/(total IO)
	FSessionIdleActiveRatio                // (H) idle vs active cycles
)

// ── Role 3: Control-Pivot (48-72) — 14 network + 11 host ──────────────
const (
	FPivotInboundOutboundRatio     = iota + 48 // (N) inbound/outbound balance
	FPivotThroughputSymmetry                    // (N) BPS rate symmetry
	FPivotIOBalance                             // (N) cumulative read/write balance
	FPivotMultiplexRatio                        // (N) clients per listener
	FPivotFanOutFromListener                    // (N) outbound when has listener
	FPivotPortDiversityThruProcess              // (N) distinct outbound ports through listener
	FPivotLoopbackRelayToExternal               // (N) loopback in → external out
	FPivotExternalRelayToLoopback               // (N) external in → loopback out
	FPivotConcurrentBidirectional               // (N) min(inbound, outbound)
	FPivotSOCKSCandidate                        // (N) loopback listener + diverse ports
	FPivotIOPerClient                           // (N) bytes per inbound client
	FPivotSMBConnCount                          // (N) SMB connections
	FPivotSMBDistinctTargets                    // (N) unique SMB targets
	FPivotSMBAllInternal                        // (N) all SMB internal flag
	FPivotNamedPipeCount                        // (H) named pipes owned
	FPivotNamedPipeC2Pattern                    // (H) C2-like pipe name flag
	FPivotNamedPipeAdmin                        // (H) admin pipe name flag
	FPivotCmdHasTunnelFlags                     // (H) tunnel flags in cmdline
	FPivotHasProxyLib                           // (H) proxy/tunnel library loaded
	FPivotListenerCount                         // (H) listener port count
	FPivotListenerLoopbackOnly                  // (H) all listeners on loopback
	FPivotListenerEphemeral                     // (H) listener on high port
	FPivotListenerPortSpread                    // (H) port range spread
	FPivotIntegrityLevel                        // (H) integrity level
	FPivotIsServiceContext                      // (H) runs as service flag
)

// ── Role 4: Outbound (73-94) — 11 network + 11 host ───────────────────
const (
	FOutboundExternalRatio        = iota + 73 // (N) fraction external
	FOutboundDistinctPrefixes                 // (N) subnet diversity
	FOutboundShortLivedRatio                  // (N) fraction short-lived
	FOutboundLongLivedRatio                   // (N) fraction long-lived
	FOutboundWellKnownPortRatio               // (N) fraction standard ports
	FOutboundConnDistinctPorts                // (N) port diversity
	FOutboundConnOutTotal                     // (N) total outbound
	FOutboundConnOutLoopback                  // (N) loopback connections
	FOutboundRareDestPort                     // (N) unusual port flag
	FOutboundRareDestPrefix                   // (N) unusual subnet flag
	FOutboundIORateTotal                      // (N) throughput rate
	FOutboundIOReadRatio                      // (H) read/(read+write)
	FOutboundIOTotalBytes                     // (H) total bytes
	FOutboundKnownVendor                      // (H) vendor recognition flag
	FOutboundKnownNetworkActive               // (H) known network app flag
	FOutboundCompanyNetworkAligned             // (H) vendor/ASN match
	FOutboundProcessIsLOLBin                  // (H) LOLBin flag
	FOutboundProcessIsScripting               // (H) script engine flag
	FOutboundSuspiciousPath                   // (H) user-writable path flag
	FOutboundProcessNameEntropy               // (H) name randomization
	FOutboundPathDepth                        // (H) path depth
	FOutboundBenignClient                     // (H) trusted directory flag
)

// ── Role 5: Listener (95-116) — 11 network + 11 host ──────────────────
const (
	FListenerPortCount               = iota + 95 // (N) distinct listener ports
	FListenerPortMin                              // (N) lowest port
	FListenerPortMax                              // (N) highest port
	FListenerWildcardCount                        // (N) 0.0.0.0 bindings
	FListenerLoopbackCount                        // (N) 127.0.0.1 bindings
	FListenerUDPCount                             // (N) UDP listeners
	FListenerInboundTotal                         // (N) inbound connections
	FListenerInboundExternal                      // (N) external inbound
	FListenerInboundInternal                      // (N) internal inbound
	FListenerDistinctClients                      // (N) unique inbound sources
	FListenerNoOutbound                           // (N) zero outbound flag
	FListenerIsServiceContext                     // (H) service account flag
	FListenerProcessAgeSec                        // (H) process age
	FListenerIOTotalRate                          // (H) throughput rate
	FListenerProcessMemMB                         // (H) working set MB
	FListenerHasRawSocket                         // (H) raw socket flag
	FListenerHasNamedPipes                        // (H) has named pipes
	FListenerChildCount                           // (H) child process count
	FListenerHighPort                             // (H) all ports >1024 flag
	FListenerConnSamePortRatio                    // (H) traffic on primary port
	FListenerInboundLoopback                      // (H) loopback inbound count
	FListenerEstablishedOnListenerPorts            // (H) ESTABLISHED on listener ports

	// Cross-role disambiguation features (117-119).
	FBeaconOutLongLivedCount    // (N) long-lived outbound connections — 0 for beacons, >=1 for sessions
	FBeaconReconnectCount       // (N) connection teardown/recreate cycles — high for beacons
	FSessionIOActiveRatio       // (H) fraction of observation time with active IO — high for sessions

	// Online verification features (120-121). Populated only when
	// PROXYWATCH_ONLINE_VERIFY=live on a platform with Authenticode
	// (Windows) or a pre-populated cache from any source. Default is
	// zero on Linux/macOS and on cache-miss, so an untrained instance
	// degrades to the 120-feature behavior by never setting them.
	FOnlineKnownBenign    // (H) 1.0 when SignatureTrust=trusted and OCSP response was seen
	FOnlineKnownMalicious // (H) 1.0 when SignatureTrust=untrusted (distrust or revoked chain)
)

var featureNames = [MaxFeatures]string{
	// Role 1: Control-Beacon (0-23)
	"beacon_interval_ms_confirmed", "beacon_jitter_cov", "beacon_syn_cycle_count",
	"beacon_callback_success_rate", "beacon_target_stability", "beacon_port_consistency",
	"beacon_ssl_likely", "beacon_multi_target", "beacon_conn_per_burst",
	"beacon_drift_rate", "beacon_interval_autocorrelation", "beacon_hits_count",
	"beacon_io_per_second_avg", "beacon_io_read_ratio", "beacon_payload_size_mean",
	"beacon_sleep_regularity", "beacon_burst_silence_shape", "beacon_cpu_to_age_ratio",
	"beacon_memory_variance", "beacon_child_count", "beacon_has_crypto_lib",
	"beacon_jitter_entropy", "beacon_long_interval", "beacon_io_zero_periods",

	// Role 2: Control-Session (24-47)
	"session_control_duration_sec", "session_conn_lifetime_max_sec", "session_distinct_targets",
	"session_external_conn_count", "session_conn_churn_rate", "session_io_write_ratio",
	"session_asn_mismatch", "session_pre_existing", "session_control_channel_age_sec",
	"session_internal_conn_count", "session_io_current_rate",
	"session_io_rw_balance", "session_io_burstiness", "session_integrity_level",
	"session_cmd_length", "session_cmd_has_encoded", "session_child_process_count",
	"session_child_is_lolbin", "session_delegated_egress_strong", "session_parent_score",
	"session_rare_parent", "session_cpu_to_io_ratio", "session_io_other_ratio",
	"session_idle_active_ratio",

	// Role 3: Control-Pivot (48-72)
	"pivot_inbound_outbound_ratio", "pivot_throughput_symmetry", "pivot_io_balance",
	"pivot_multiplex_ratio", "pivot_fan_out_from_listener", "pivot_port_diversity_through_process",
	"pivot_loopback_relay_to_external", "pivot_external_relay_to_loopback",
	"pivot_concurrent_bidirectional", "pivot_socks_candidate", "pivot_io_per_client",
	"pivot_smb_conn_count", "pivot_smb_distinct_targets", "pivot_smb_all_internal",
	"pivot_named_pipe_count", "pivot_named_pipe_c2_pattern", "pivot_named_pipe_admin",
	"pivot_cmd_has_tunnel_flags", "pivot_has_proxy_lib", "pivot_listener_count",
	"pivot_listener_loopback_only", "pivot_listener_ephemeral", "pivot_listener_port_spread",
	"pivot_integrity_level", "pivot_is_service_context",

	// Role 4: Outbound (73-94)
	"outbound_external_ratio", "outbound_distinct_prefixes", "outbound_short_lived_ratio",
	"outbound_long_lived_ratio", "outbound_well_known_port_ratio", "outbound_conn_distinct_ports",
	"outbound_conn_out_total", "outbound_conn_out_loopback", "outbound_rare_dest_port",
	"outbound_rare_dest_prefix", "outbound_io_rate_total",
	"outbound_io_read_ratio", "outbound_io_total_bytes", "outbound_known_vendor",
	"outbound_known_network_active", "outbound_company_network_aligned",
	"outbound_process_is_lolbin", "outbound_process_is_scripting",
	"outbound_suspicious_path", "outbound_process_name_entropy", "outbound_path_depth",
	"outbound_benign_client",

	// Role 5: Listener (95-116)
	"listener_port_count", "listener_port_min", "listener_port_max",
	"listener_wildcard_count", "listener_loopback_count", "listener_udp_count",
	"listener_inbound_total", "listener_inbound_external", "listener_inbound_internal",
	"listener_distinct_clients", "listener_no_outbound",
	"listener_is_service_context", "listener_process_age_sec", "listener_io_total_rate",
	"listener_process_mem_mb", "listener_has_raw_socket", "listener_has_named_pipes",
	"listener_child_count", "listener_high_port", "listener_conn_same_port_ratio",
	"listener_inbound_loopback", "listener_established_on_listener_ports",

	// Cross-role disambiguation (117-119)
	"beacon_out_long_lived_count", "beacon_reconnect_count", "session_io_active_ratio",

	// Online verification (120-121)
	"online_known_benign", "online_known_malicious",
}
