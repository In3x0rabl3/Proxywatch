package behavior

import "testing"

func TestMatchesSaaSC2(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Positive — exact and subdomain matches.
		{"slack.com", true},
		{"edge-turn-msft.slack.com", true},
		{"api.github.com", true},
		{"raw.githubusercontent.com", true},
		{"cdn.discordapp.com", true},
		{"hivemq.cloud", true},
		{"broker-abc.hivemq.cloud", true},
		{"api.telegram.org", true},

		// Case-insensitivity and whitespace.
		{"  SLACK.COM  ", true},
		{"API.GitHub.com", true},

		// Negative — substring-not-suffix, lookalikes, unrelated.
		{"", false},
		{"notslack.com", false},                     // not a subdomain of slack.com
		{"slack.com.attacker.example", false},       // dot-suffix attack — NOT a match
		{"discord.com.fake-phishing.org", false},    // same pattern
		{"example.com", false},
		{"10.0.0.1", false},
		{"slack.attacker.example", false},           // reverse direction
	}
	for _, tc := range cases {
		if got := matchesSaaSC2(tc.host); got != tc.want {
			t.Errorf("matchesSaaSC2(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
