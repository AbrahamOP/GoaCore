package handlers

import (
	"encoding/json"
	"net/http"
)

// HandleNotificationStatus reports the live notification capability of the server.
//
// "supported" advertises that the server-side notification surface exists at all
// (the browser Notification API is a separate, client-side concern the front-end
// probes on its own). "discord" reflects the REAL runtime state: whether a Discord
// bot session is currently live in the service registry (configured + hot-loaded via
// the Connexions page). It is false on a vierge instance or when Discord is disabled,
// so the UI never claims a delivery channel that is not actually wired.
func (h *Handler) HandleNotificationStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"supported": true,
		"discord":   h.Registry.Discord() != nil,
	})
}
