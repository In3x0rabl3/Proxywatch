package output

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/ingestion/azlogs"

	"proxywatch/internal/shared"
)

const (
	SentinelAuthManagedIdentity = "managed_identity"
	SentinelAuthClientSecret    = "client_secret"

	sentinelSchemaVersion = "proxywatch.sentinel.v1"
	sentinelQueueDepth    = 16
	sentinelUploadTimeout = 15 * time.Second
	// Azure Monitor's Logs Ingestion API rejects requests larger than 1 MB.
	// Leave headroom for transport-level framing and future schema additions.
	sentinelMaxBatchBytes = 900 * 1024
)

// SentinelConfig configures Azure Monitor Logs Ingestion for Microsoft
// Sentinel. Endpoint is the DCE logs ingestion endpoint (or a direct DCR logs
// endpoint), and DCRID is the DCR immutable ID beginning with "dcr-".
type SentinelConfig struct {
	AuthMode     string
	Endpoint     string
	DCRID        string
	StreamName   string
	TenantID     string
	ClientID     string
	ClientSecret string
}

// SentinelDetectionEvent is deliberately flat and strongly typed so a DCR can
// map it directly into a custom Log Analytics table. Arrays and connection
// collections are the only dynamic columns.
type SentinelDetectionEvent struct {
	TimeGenerated          time.Time                   `json:"TimeGenerated"`
	SchemaVersion          string                      `json:"SchemaVersion"`
	EventType              string                      `json:"EventType"`
	EntityID               string                      `json:"EntityId"`
	DetectionID            string                      `json:"DetectionId"`
	Cycle                  uint64                      `json:"Cycle"`
	Host                   string                      `json:"Host"`
	ProcessID              int                         `json:"ProcessId"`
	ProcessName            string                      `json:"ProcessName"`
	ProcessPath            string                      `json:"ProcessPath,omitempty"`
	User                   string                      `json:"User,omitempty"`
	Role                   string                      `json:"Role"`
	RoleFamily             string                      `json:"RoleFamily"`
	State                  string                      `json:"State"`
	Score                  int                         `json:"Score"`
	Confidence             int                         `json:"Confidence"`
	StrongEvidence         bool                        `json:"StrongEvidence"`
	ActiveProxying         bool                        `json:"ActiveProxying"`
	TrafficVerified        bool                        `json:"TrafficVerified"`
	InboundTotal           int                         `json:"InboundTotal"`
	OutboundTotal          int                         `json:"OutboundTotal"`
	OutboundExternal       int                         `json:"OutboundExternal"`
	OutboundInternal       int                         `json:"OutboundInternal"`
	OutboundLoopback       int                         `json:"OutboundLoopback"`
	TCPListenerCount       int                         `json:"TcpListenerCount"`
	UDPListenerCount       int                         `json:"UdpListenerCount"`
	ControlDurationSeconds int                         `json:"ControlDurationSeconds"`
	ControlRemoteAddress   string                      `json:"ControlRemoteAddress,omitempty"`
	ControlRemotePort      int                         `json:"ControlRemotePort,omitempty"`
	Signals                []string                    `json:"Signals,omitempty"`
	Reasons                []string                    `json:"Reasons,omitempty"`
	Connections            []DefenderConnIndicator     `json:"Connections,omitempty"`
	TCPListeners           []DefenderListenerIndicator `json:"TcpListeners,omitempty"`
	UDPListeners           []DefenderListenerIndicator `json:"UdpListeners,omitempty"`
}

type sentinelUploader interface {
	Upload(context.Context, string, string, []byte, *azlogs.UploadOptions) (azlogs.UploadResponse, error)
}

type sentinelSender struct {
	ruleID     string
	streamName string
	uploader   sentinelUploader
	queue      chan []SentinelDetectionEvent
	cancel     context.CancelFunc
	observedMu sync.Mutex
	observed   map[string]sentinelObservation
}

type sentinelObservation struct {
	fingerprint string
	event       SentinelDetectionEvent
}

var (
	sentinelMu      sync.RWMutex
	currentSentinel *sentinelSender
)

// ConfigureSentinelOutput enables the Sentinel output. Supplying no endpoint,
// DCR ID, and stream name disables it. Managed identity is the default mode;
// ClientID optionally selects a user-assigned identity. Client-secret mode
// requires TenantID, ClientID, and ClientSecret.
func ConfigureSentinelOutput(cfg SentinelConfig) error {
	var err error
	cfg, err = normalizeSentinelConfig(cfg)
	if err != nil {
		return err
	}
	if cfg.Endpoint == "" {
		replaceSentinelSender(nil)
		return nil
	}

	credential, err := sentinelCredential(cfg)
	if err != nil {
		return fmt.Errorf("configure Sentinel credential: %w", err)
	}
	client, err := azlogs.NewClient(cfg.Endpoint, credential, nil)
	if err != nil {
		return fmt.Errorf("configure Sentinel Logs Ingestion client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sender := &sentinelSender{
		ruleID:     cfg.DCRID,
		streamName: cfg.StreamName,
		uploader:   client,
		queue:      make(chan []SentinelDetectionEvent, sentinelQueueDepth),
		cancel:     cancel,
		observed:   make(map[string]sentinelObservation),
	}
	replaceSentinelSender(sender)
	go sender.run(ctx)
	return nil
}

func normalizeSentinelConfig(cfg SentinelConfig) (SentinelConfig, error) {
	cfg.AuthMode = strings.ToLower(strings.TrimSpace(cfg.AuthMode))
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	cfg.DCRID = strings.TrimSpace(cfg.DCRID)
	cfg.StreamName = strings.TrimSpace(cfg.StreamName)
	cfg.TenantID = strings.TrimSpace(cfg.TenantID)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)

	if cfg.Endpoint == "" && cfg.DCRID == "" && cfg.StreamName == "" {
		return SentinelConfig{}, nil
	}
	if cfg.Endpoint == "" || cfg.DCRID == "" || cfg.StreamName == "" {
		return SentinelConfig{}, fmt.Errorf("Sentinel output requires DCE endpoint, DCR immutable ID, and stream name")
	}
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return SentinelConfig{}, fmt.Errorf("invalid Sentinel DCE endpoint %q: expected an HTTPS origin", cfg.Endpoint)
	}
	if !strings.HasPrefix(strings.ToLower(cfg.DCRID), "dcr-") {
		return SentinelConfig{}, fmt.Errorf("invalid Sentinel DCR immutable ID %q: expected dcr- prefix", cfg.DCRID)
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = SentinelAuthManagedIdentity
	}
	switch cfg.AuthMode {
	case SentinelAuthManagedIdentity:
	case SentinelAuthClientSecret:
		if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
			return SentinelConfig{}, fmt.Errorf("Sentinel client_secret authentication requires tenant ID, client ID, and client secret")
		}
	default:
		return SentinelConfig{}, fmt.Errorf("unsupported Sentinel authentication mode %q", cfg.AuthMode)
	}
	return cfg, nil
}

func sentinelCredential(cfg SentinelConfig) (azcore.TokenCredential, error) {
	if cfg.AuthMode == SentinelAuthClientSecret {
		return azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)
	}
	options := &azidentity.ManagedIdentityCredentialOptions{}
	if cfg.ClientID != "" {
		options.ID = azidentity.ClientID(cfg.ClientID)
	}
	return azidentity.NewManagedIdentityCredential(options)
}

func replaceSentinelSender(sender *sentinelSender) {
	sentinelMu.Lock()
	previous := currentSentinel
	currentSentinel = sender
	sentinelMu.Unlock()
	if previous != nil && previous.cancel != nil {
		previous.cancel()
	}
}

// SentinelOutputConfigured reports whether uploads are enabled.
func SentinelOutputConfigured() bool {
	sentinelMu.RLock()
	configured := currentSentinel != nil
	sentinelMu.RUnlock()
	return configured
}

// EmitSentinelDetections queues flat lifecycle events for flagged candidates.
// Queueing is non-blocking so Azure availability cannot stall classification.
func EmitSentinelDetections(now time.Time, cycle uint64, hostScope string, flagged []shared.Candidate) {
	sentinelMu.RLock()
	sender := currentSentinel
	sentinelMu.RUnlock()
	if sender == nil {
		return
	}

	events := BuildSentinelDetectionEvents(now, cycle, hostScope, flagged)
	events, nextObserved := sender.changedEvents(now, cycle, events)
	if len(events) == 0 {
		sender.observedMu.Unlock()
		return
	}
	select {
	case sender.queue <- events:
		sender.observed = nextObserved
	default:
		ReportDetectionOutputError(fmt.Errorf("Sentinel output queue is full; dropped %d detection events", len(events)))
	}
	sender.observedMu.Unlock()
}

// changedEvents returns lifecycle and material-evidence changes. It leaves
// observedMu locked so the caller can advance state only after the queue
// accepts the batch.
func (s *sentinelSender) changedEvents(now time.Time, cycle uint64, current []SentinelDetectionEvent) ([]SentinelDetectionEvent, map[string]sentinelObservation) {
	s.observedMu.Lock()
	next := make(map[string]sentinelObservation, len(current))
	changes := make([]SentinelDetectionEvent, 0, len(current))

	for _, event := range current {
		fingerprint := sentinelEventFingerprint(event)
		previous, exists := s.observed[event.EntityID]
		if !exists {
			event.EventType = "DetectionCreated"
			changes = append(changes, event)
		} else if previous.fingerprint != fingerprint {
			event.EventType = "DetectionUpdated"
			changes = append(changes, event)
		}
		next[event.EntityID] = sentinelObservation{fingerprint: fingerprint, event: event}
	}

	for entityID, previous := range s.observed {
		if _, exists := next[entityID]; exists {
			continue
		}
		resolved := previous.event
		resolved.TimeGenerated = now.UTC()
		resolved.Cycle = cycle
		resolved.EventType = "DetectionResolved"
		resolved.State = "resolved"
		resolved.ActiveProxying = false
		changes = append(changes, resolved)
	}
	return changes, next
}

func sentinelEventFingerprint(event SentinelDetectionEvent) string {
	shape := struct {
		Role                 string
		RoleFamily           string
		State                string
		ScoreBand            int
		ConfidenceBand       int
		StrongEvidence       bool
		ActiveProxying       bool
		TrafficVerified      bool
		ControlRemoteAddress string
		ControlRemotePort    int
		Signals              []string
		Reasons              []string
		Connections          []DefenderConnIndicator
		TCPListeners         []DefenderListenerIndicator
		UDPListeners         []DefenderListenerIndicator
	}{
		Role:                 event.Role,
		RoleFamily:           event.RoleFamily,
		State:                event.State,
		ScoreBand:            event.Score / 10,
		ConfidenceBand:       event.Confidence / 10,
		StrongEvidence:       event.StrongEvidence,
		ActiveProxying:       event.ActiveProxying,
		TrafficVerified:      event.TrafficVerified,
		ControlRemoteAddress: event.ControlRemoteAddress,
		ControlRemotePort:    event.ControlRemotePort,
		Signals:              event.Signals,
		Reasons:              event.Reasons,
		Connections:          event.Connections,
		TCPListeners:         event.TCPListeners,
		UDPListeners:         event.UDPListeners,
	}
	body, _ := json.Marshal(shape)
	return string(body)
}

func (s *sentinelSender) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case events := <-s.queue:
			batches, err := marshalSentinelBatches(events, sentinelMaxBatchBytes)
			if err != nil {
				ReportDetectionOutputError(err)
				continue
			}
			for _, body := range batches {
				uploadCtx, cancel := context.WithTimeout(ctx, sentinelUploadTimeout)
				_, err = s.uploader.Upload(uploadCtx, s.ruleID, s.streamName, body, nil)
				cancel()
				if err != nil {
					ReportDetectionOutputError(fmt.Errorf("Sentinel Logs Ingestion upload: %w", err))
					break
				}
			}
		}
	}
}

// BuildSentinelDetectionEvents converts candidates into the stable DCR input
// schema documented in docs/sentinel.md.
func BuildSentinelDetectionEvents(now time.Time, cycle uint64, hostScope string, candidates []shared.Candidate) []SentinelDetectionEvent {
	events := make([]SentinelDetectionEvent, 0, len(candidates))
	for _, candidate := range candidates {
		item := MakeDefenderCandidateItem(candidate, hostScope)
		event := SentinelDetectionEvent{
			TimeGenerated:          now.UTC(),
			SchemaVersion:          sentinelSchemaVersion,
			EventType:              "DetectionObservation",
			EntityID:               BuildSentinelEntityID(item.Host, item.PID),
			DetectionID:            item.DetectionID,
			Cycle:                  cycle,
			Host:                   item.Host,
			ProcessID:              item.PID,
			ProcessName:            item.Process,
			ProcessPath:            item.ProcessPath,
			User:                   item.User,
			Role:                   item.Role,
			RoleFamily:             item.RoleFamily,
			State:                  item.State,
			Score:                  item.Score,
			Confidence:             item.Confidence,
			StrongEvidence:         item.StrongEvidence,
			ActiveProxying:         item.Active,
			TrafficVerified:        item.TrafficVerified,
			InboundTotal:           candidate.InboundTotal,
			OutboundTotal:          candidate.OutTotal,
			OutboundExternal:       candidate.OutExternal,
			OutboundInternal:       candidate.OutInternal,
			OutboundLoopback:       candidate.OutLoopback,
			TCPListenerCount:       len(candidate.Listeners),
			UDPListenerCount:       len(candidate.UDPListeners),
			ControlDurationSeconds: candidate.ControlDurationSeconds,
			Signals:                item.Signals,
			Reasons:                item.Reasons,
			Connections:            item.Connections,
			TCPListeners:           item.TCPListeners,
			UDPListeners:           item.UDPListeners,
		}
		if item.ControlChannel != nil {
			event.ControlRemoteAddress = item.ControlChannel.RemoteAddress
			event.ControlRemotePort = item.ControlChannel.RemotePort
		}
		events = append(events, event)
	}
	return events
}

// BuildSentinelEntityID remains stable across role transitions so created,
// updated, and resolved events can be correlated in KQL.
func BuildSentinelEntityID(host string, pid int) string {
	return SanitizeIDPart(host) + "-" + fmt.Sprintf("%d", pid)
}

func marshalSentinelBatches(events []SentinelDetectionEvent, maxBytes int) ([][]byte, error) {
	if len(events) == 0 {
		return nil, nil
	}
	if maxBytes < 3 {
		return nil, fmt.Errorf("invalid Sentinel maximum batch size %d", maxBytes)
	}

	var batches [][]byte
	batch := make([]json.RawMessage, 0, len(events))
	batchSize := 2 // opening and closing JSON array brackets
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		body, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		batches = append(batches, body)
		batch = nil
		batchSize = 2
		return nil
	}

	for _, event := range events {
		record, err := json.Marshal(event)
		if err != nil {
			return nil, fmt.Errorf("marshal Sentinel detection event: %w", err)
		}
		separator := 0
		if len(batch) > 0 {
			separator = 1
		}
		if len(record)+2 > maxBytes {
			return nil, fmt.Errorf("Sentinel detection event %q exceeds the upload size limit", event.DetectionID)
		}
		if batchSize+separator+len(record) > maxBytes {
			if err := flush(); err != nil {
				return nil, err
			}
			separator = 0
		}
		batch = append(batch, json.RawMessage(record))
		batchSize += separator + len(record)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return batches, nil
}
