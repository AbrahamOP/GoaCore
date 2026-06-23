package services

import (
	"strings"
)

// TestConnectionResult is the structured outcome of a live Proxmox connection
// test. Kind classifies the failure so the UI (and the Save gate) can react
// differently: a transient network/TLS error may be overridden by the admin
// ("save anyway"), whereas an auth failure (401/403) is a hard block.
type TestConnectionResult struct {
	OK    bool   // true when /nodes answered and a node status was read
	Node  string // node the API resolved against (best-effort)
	Kind  string // "", "network", "auth", "no_node", "api"
	Error string // human-readable message (never contains the secret)
}

// Test-result kinds. Exported so handlers can branch on them without string
// literals (the Save gate distinguishes transient "network" from hard "auth").
const (
	TestKindNetwork = "network" // timeout / TLS / DNS — transient, "save anyway" allowed
	TestKindAuth    = "auth"    // 401/403 bad token — hard block, Save refused
	TestKindNoNode  = "no_node" // reachable + authenticated but zero nodes
	TestKindAPI     = "api"     // other non-2xx / decode error from the API
)

// TestConnection performs a live, read-only probe of a Proxmox connection and
// classifies the outcome. It first calls probeNodes (GET /api2/json/nodes, 5s
// timeout) so it can robustly detect the "authenticated but zero nodes" case from
// the actual node COUNT — GetStats can't surface that, since it auto-resolves the
// target node to the first entry the moment the list is non-empty. It then delegates
// to GetStats to validate the node-status read. It persists NOTHING — it is purely
// the engine behind the onboarding "Tester la connexion" button and the server-side
// re-test at Save.
//
// A successful test proves auth + reachability, NOT write ACLs: a token with
// only PVEAuditor still returns nodes here while being unable to create or power
// guests. Callers should communicate this distinction to the operator.
func (p *ProxmoxService) TestConnection(rawURL, node, tokenID, secret string) TestConnectionResult {
	if strings.TrimSpace(rawURL) == "" || strings.TrimSpace(tokenID) == "" || strings.TrimSpace(secret) == "" {
		return TestConnectionResult{
			Kind:  TestKindAuth,
			Error: "URL, identifiant et secret du token sont requis.",
		}
	}

	// Probe /nodes directly to read the node count (auth + reachability + 0-node).
	nodes, err := p.probeNodes(rawURL, tokenID, secret)
	if err != nil {
		return classifyTestError(err)
	}
	if len(nodes) == 0 {
		// /nodes answered 200 but the cluster exposes no node to this token. This is
		// now detected from the real count, not a brittle error substring.
		return TestConnectionResult{
			Kind:  TestKindNoNode,
			Error: "Connexion authentifiée mais aucun node Proxmox disponible.",
		}
	}

	// At least one node exists: validate the node-status read via GetStats (resolves
	// the target node and confirms a 2xx status). Any failure here is auth/api/network.
	if _, err := p.GetStats(rawURL, node, tokenID, secret, false, false); err != nil {
		return classifyTestError(err)
	}

	return TestConnectionResult{OK: true, Node: node}
}

// classifyTestError maps a probeNodes / GetStats error into a TestConnectionResult
// kind. The error strings come from probeNodes ("Network error (Nodes): ..." /
// "API Error Nodes HTTP 401: ...") and from GetStats ("Network error: ..." /
// "API Error Node Status (...) HTTP 401/403: ..."). HTTP 401/403 from either path
// is auth; transport/TLS/timeout is network; anything else is a generic API error.
//
// The zero-node case is no longer inferred from an error substring here — it is
// detected up-front in TestConnection from the real node count returned by
// probeNodes. The legacy "API Error Node Status ()" branch is kept only as a
// defensive fallback (it was practically unreachable, since GetStats auto-resolves
// the target node to the first discovered node).
func classifyTestError(err error) TestConnectionResult {
	msg := err.Error()
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "network error"):
		return TestConnectionResult{
			Kind:  TestKindNetwork,
			Error: "Erreur réseau : Proxmox injoignable (timeout, DNS ou TLS). " + cleanNetworkError(msg),
		}
	case strings.Contains(msg, "HTTP 401") || strings.Contains(msg, "HTTP 403"):
		return TestConnectionResult{
			Kind:  TestKindAuth,
			Error: "Authentification refusée (HTTP 401/403) : vérifiez l'identifiant et le secret du token.",
		}
	case strings.Contains(msg, "API Error Node Status ()"):
		// Defensive fallback: an empty target node (zero nodes) reaching the status
		// call. Practically unreachable now that TestConnection counts nodes first.
		return TestConnectionResult{
			Kind:  TestKindNoNode,
			Error: "Connexion authentifiée mais aucun node Proxmox disponible.",
		}
	default:
		return TestConnectionResult{
			Kind:  TestKindAPI,
			Error: "Erreur API Proxmox : " + msg,
		}
	}
}

// cleanNetworkError strips the "Network error[ (Nodes)]: " prefix so the UI
// message reads naturally after our own French prefix.
func cleanNetworkError(msg string) string {
	for _, pfx := range []string{"Network error (Nodes): ", "Network error: "} {
		if strings.HasPrefix(msg, pfx) {
			return strings.TrimPrefix(msg, pfx)
		}
	}
	return msg
}
