package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func (h *Handler) HandleTogglePin(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("id")
	if appID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing id"})
		return
	}

	// Toggle is_pinned
	_, err := h.DB.Exec("UPDATE apps SET is_pinned = NOT is_pinned WHERE id = ?", appID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Read back the new state so the client can reflect it without a refresh.
	// A read failure here doesn't undo the toggle (the UPDATE already committed),
	// so log it and report ok with the zero value rather than 500 — but never
	// silently let a stale `pinned:false` desync the UI without a trace.
	var pinned bool
	if err := h.DB.QueryRow("SELECT is_pinned FROM apps WHERE id = ?", appID).Scan(&pinned); err != nil {
		slog.Error("Error reading back pin state after toggle", "appID", appID, "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "pinned": pinned})
}
