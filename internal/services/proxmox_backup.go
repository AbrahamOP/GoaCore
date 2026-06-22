package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"goacloud/internal/models"
)

// pveStorageContent mirrors the Proxmox storage content listing (content=backup).
type pveStorageContent struct {
	Data []struct {
		VolID   string      `json:"volid"`
		Format  string      `json:"format"`
		Size    int64       `json:"size"`
		CTime   int64       `json:"ctime"`
		VMID    json.Number `json:"vmid"`
		Notes   string      `json:"notes"`
		Content string      `json:"content"`
	} `json:"data"`
}

// hostBaseURL normalises a raw Proxmox URL down to scheme://host.
func (p *ProxmoxService) hostBaseURL(rawURL string) string {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		baseURL = u.Scheme + "://" + u.Host
	}
	return baseURL
}

// resolveNode returns the configured node if online, else the first online node.
func (p *ProxmoxService) resolveNode(client *http.Client, baseURL, configuredNode, tokenID, secret string) string {
	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	reqNodes.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	respNodes, err := client.Do(reqNodes)
	if err != nil {
		return targetNode
	}
	defer respNodes.Body.Close()
	if respNodes.StatusCode != 200 {
		return targetNode
	}
	var nodeList models.PveNodesList
	if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err != nil {
		return targetNode
	}
	firstOnline := ""
	for _, n := range nodeList.Data {
		if n.Status == "online" {
			if firstOnline == "" {
				firstOnline = n.Node
			}
			if n.Node == configuredNode {
				return configuredNode
			}
		}
	}
	if firstOnline != "" {
		return firstOnline
	}
	return targetNode
}

// ListBackups returns vzdump backup archives present on the given storage.
func (p *ProxmoxService) ListBackups(rawURL, configuredNode, tokenID, secret, storage string) ([]models.BackupEntry, error) {
	baseURL := p.hostBaseURL(rawURL)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}
	targetNode := p.resolveNode(client, baseURL, configuredNode, tokenID, secret)

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/storage/%s/content?content=backup",
		baseURL, targetNode, url.PathEscape(storage))
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var content pveStorageContent
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, err
	}

	entries := make([]models.BackupEntry, 0, len(content.Data))
	for _, item := range content.Data {
		vmid := 0
		if item.VMID != "" {
			vmid, _ = strconv.Atoi(item.VMID.String())
		}
		if vmid == 0 {
			vmid = parseVMIDFromVolID(item.VolID)
		}
		typ := "qemu"
		if strings.Contains(item.VolID, "vzdump-lxc-") {
			typ = "lxc"
		}
		entries = append(entries, models.BackupEntry{
			VolID:     item.VolID,
			VMID:      vmid,
			Type:      typ,
			Storage:   storage,
			SizeBytes: item.Size,
			CTime:     time.Unix(item.CTime, 0),
			Notes:     item.Notes,
			Format:    item.Format,
		})
	}
	return entries, nil
}

// parseVMIDFromVolID extracts the VMID from a vzdump volid as a fallback.
// e.g. "local:backup/vzdump-lxc-110-2026_06_22-03_19_36.tar.zst" -> 110
func parseVMIDFromVolID(volid string) int {
	base := volid
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	parts := strings.Split(base, "-")
	if len(parts) >= 3 {
		if n, err := strconv.Atoi(parts[2]); err == nil {
			return n
		}
	}
	return 0
}
