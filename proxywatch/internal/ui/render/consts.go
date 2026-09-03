package render

// Field constants duplicated from internal/ui/keys/shared.go so the render
// package can reference them without importing the keys package
// (which would create a circular dependency: keys → views → render).
// Canonical source: internal/ui/keys/shared.go — keep these in sync.

const (
	collectFieldSource = iota
	collectFieldOutput
	collectFieldDuration
	collectFieldAction
)

const (
	whitelistFieldProcess = iota
	whitelistFieldEntry
	whitelistFieldAdd
	whitelistFieldRemove
)

const (
	contourFieldSource = iota
	contourFieldEndpoint
	contourFieldOutput
	contourFieldDuration
	contourFieldProbeMode
	contourFieldProbeRole
	contourFieldAction
)

const (
	keystoreFieldOpenAIKey = iota
	keystoreFieldOpenAIBaseURL
	keystoreFieldAnthropicKey
	keystoreFieldAnthropicBaseURL
	keystoreFieldLocalLLMURL
	keystoreFieldLocalLLMAPIKey
	keystoreFieldCalibrationTimeout
	keystoreFieldProxyhoundURL
	keystoreFieldProxyhoundToken
	keystoreFieldProxyhoundTokenID
	keystoreFieldTLSDir
	keystoreFieldAgentToken
	keystoreFieldDisableClientCert
	keystoreFieldTrustOnFirstUse
	keystoreFieldMethod
	keystoreFieldGitHubToken
	keystoreFieldBuildkiteToken
	keystoreFieldAWSAccessKey
	keystoreFieldAWSSecretKey
	keystoreFieldAzureClientID
	keystoreFieldAzureClientSecret
	keystoreFieldGCPServiceKey
	keystoreFieldSlackBotToken
	keystoreFieldDiscordBotToken
	keystoreFieldTelegramBotKey
	keystoreFieldFirebaseKey
	keystoreFieldTeamsAuth
	keystoreFieldGitLabToken
	keystoreFieldSave
	keystoreFieldApply
	keystoreFieldLock
	keystoreFieldLoad
	keystoreFieldNew
)

const keystoreFieldMax = keystoreFieldNew
