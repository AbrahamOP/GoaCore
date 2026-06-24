package services

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"goacore/internal/config"
	"goacore/internal/models"
)

// ProxmoxService handles all Proxmox API interactions.
type ProxmoxService struct {
	db      *sql.DB
	skipTLS bool
}

// NewProxmoxService creates a new ProxmoxService.
func NewProxmoxService(db *sql.DB, skipTLS bool) *ProxmoxService {
	return &ProxmoxService{db: db, skipTLS: skipTLS}
}

func (p *ProxmoxService) tlsConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: p.skipTLS} //nolint:gosec
}

// probeNodes performs the bare GET /api2/json/nodes call and returns the decoded
// node list. It is the shared first step of GetStats and the connection test: the
// latter needs the raw node COUNT to distinguish "authenticated but zero nodes"
// from a normal run, which it cannot infer from GetStats' error strings (GetStats
// auto-resolves targetNode to the first node the moment the list is non-empty).
// A non-2xx status is returned as an error carrying the HTTP code so the caller can
// classify auth (401/403) vs other API failures.
func (p *ProxmoxService) probeNodes(rawURL, tokenID, secret string) ([]models.PveNode, error) {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Network error (Nodes): %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API Error Nodes HTTP %d: %s", resp.StatusCode, string(body))
	}
	var nodeList models.PveNodesList
	if err := json.Unmarshal(body, &nodeList); err != nil {
		return nil, fmt.Errorf("decode nodes: %v", err)
	}
	return nodeList.Data, nil
}

// GetStats fetches Proxmox node statistics and optionally the guest list.
func (p *ProxmoxService) GetStats(rawURL, configuredNode, tokenID, secret string, includeGuests bool, forceRealIPs bool) (models.ProxmoxStats, error) {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}
	slog.Debug("ProxmoxStats baseURL", "url", baseURL)

	stats := models.ProxmoxStats{VMs: []models.VM{}}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	headers := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// 0. Auto-discover node
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	headers(reqNodes)
	respNodes, err := client.Do(reqNodes)
	if err != nil {
		return stats, fmt.Errorf("Network error (Nodes): %v", err)
	}
	bodyNodes, _ := io.ReadAll(respNodes.Body)
	respNodes.Body.Close()

	targetNode := configuredNode
	var nodeList models.PveNodesList
	if jsonErr := json.Unmarshal(bodyNodes, &nodeList); jsonErr == nil && len(nodeList.Data) > 0 {
		found := false
		firstAny := ""
		firstOnline := ""
		for _, n := range nodeList.Data {
			if firstAny == "" {
				firstAny = n.Node
			}
			if n.Status == "online" && firstOnline == "" {
				firstOnline = n.Node
			}
			if n.Node == configuredNode {
				found = true
				break
			}
		}
		if !found {
			if firstOnline != "" {
				slog.Info("Proxmox: node not found, using online node", "configured", configuredNode, "using", firstOnline)
				targetNode = firstOnline
			} else {
				slog.Info("Proxmox: no online node, using first available", "node", firstAny)
				targetNode = firstAny
			}
		}
	} else {
		slog.Warn("Proxmox: cannot decode node list", "status", respNodes.StatusCode, "body", string(bodyNodes))
	}

	// 1. Node Status
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes/%s/status", baseURL, targetNode), nil)
	headers(req)
	resp, err := client.Do(req)
	if err != nil {
		return stats, fmt.Errorf("Network error: %v", err)
	}
	bodyStatus, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return stats, fmt.Errorf("API Error Node Status (%s) HTTP %d: %s", targetNode, resp.StatusCode, string(bodyStatus))
	}

	var nodeStatus models.PveNodeStatus
	if err := json.Unmarshal(bodyStatus, &nodeStatus); err == nil {
		stats.CPU = int(nodeStatus.Data.CPU * 100)
		stats.RAMTotal = float64(nodeStatus.Data.Memory.Total) / 1024 / 1024 / 1024
		stats.RAMUsed = float64(nodeStatus.Data.Memory.Used) / 1024 / 1024 / 1024
		stats.RAMUsedStr = fmt.Sprintf("%.2f GB", stats.RAMUsed)
		stats.RAMTotalStr = fmt.Sprintf("%.2f GB", stats.RAMTotal)
		if stats.RAMTotal > 0 {
			stats.RAM = int((stats.RAMUsed / stats.RAMTotal) * 100)
		}
		storageTotal := float64(nodeStatus.Data.Rootfs.Total)
		storageUsed := float64(nodeStatus.Data.Rootfs.Used)
		if storageTotal > 0 {
			stats.Storage = int((storageUsed / storageTotal) * 100)
		}
	} else {
		slog.Error("JSON Decode Error Node Status", "error", err)
	}

	if includeGuests {
		var allGuests []models.VM

		fetchAPI := func(endpoint, kind string) {
			req, _ := http.NewRequest("GET", endpoint, nil)
			headers(req)
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					var vms models.PveVMList
					if err := json.NewDecoder(resp.Body).Decode(&vms); err == nil {
						for _, vm := range vms.Data {
							allGuests = append(allGuests, models.VM{
								ID:     vm.VMID,
								Name:   vm.Name,
								Status: vm.Status,
								Uptime: fmt.Sprintf("%dh", vm.Uptime/3600),
								IP:     "-",
								Type:   kind,
							})
						}
					}
				}
			}
		}

		fetchAPI(fmt.Sprintf("%s/api2/json/nodes/%s/qemu", baseURL, targetNode), "VM")
		fetchAPI(fmt.Sprintf("%s/api2/json/nodes/%s/lxc", baseURL, targetNode), "CT")

		stats.VMs = allGuests

		if forceRealIPs {
			var wg sync.WaitGroup
			for i := range stats.VMs {
				if stats.VMs[i].Status != "running" {
					continue
				}
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					ip, err := p.getGuestIP(client, baseURL, targetNode, tokenID, secret, stats.VMs[idx].Type, stats.VMs[idx].ID)
					if err == nil && ip != "" {
						stats.VMs[idx].IP = ip
					}
				}(i)
			}
			wg.Wait()
		} else {
			rows, err := p.db.Query("SELECT vmid, ip_address FROM vm_cache")
			if err == nil {
				defer rows.Close()
				ipMap := make(map[int]string)
				for rows.Next() {
					var vmid int
					var ip string
					if err := rows.Scan(&vmid, &ip); err == nil {
						ipMap[vmid] = ip
					}
				}
				_ = rows.Err()
				for i := range stats.VMs {
					if val, ok := ipMap[stats.VMs[i].ID]; ok {
						stats.VMs[i].IP = val
					}
				}
			}
		}

		sort.Slice(stats.VMs, func(i, j int) bool {
			return stats.VMs[i].ID < stats.VMs[j].ID
		})
	}

	return stats, nil
}

// GetGuestDetail fetches detailed information about a specific VM/CT.
func (p *ProxmoxService) GetGuestDetail(rawURL, configuredNode, tokenID, secret, pveType, vmid string) (models.GuestDetail, error) {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	var detail models.GuestDetail
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	headers := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	targetNode := configuredNode

	// Auto-discover node
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	headers(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	urlStatus := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/status/current", baseURL, targetNode, pveType, vmid)
	req, _ := http.NewRequest("GET", urlStatus, nil)
	headers(req)
	resp, err := client.Do(req)
	if err != nil {
		return detail, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return detail, fmt.Errorf("API Status Error: %s", resp.Status)
	}

	var statusResp models.PveGuestStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return detail, err
	}

	d := statusResp.Data
	detail.ID, _ = strconv.Atoi(vmid)
	detail.Name = d.Name
	detail.Status = d.Status
	detail.Uptime = fmt.Sprintf("%dh", int(d.Uptime)/3600)
	detail.CPU = float64(int(d.CPU*10000)) / 100
	detail.Cores = d.CPUs
	detail.RAMUsed = fmt.Sprintf("%.2f GB", float64(d.Mem)/1024/1024/1024)
	detail.RAMTotal = fmt.Sprintf("%.2f GB", float64(d.MaxMem)/1024/1024/1024)
	if d.MaxMem > 0 {
		detail.RAMPercent = int((float64(d.Mem) / float64(d.MaxMem)) * 100)
	}
	detail.DiskUsed = fmt.Sprintf("%.2f GB", float64(d.Disk)/1024/1024/1024)
	detail.DiskTotal = fmt.Sprintf("%.2f GB", float64(d.MaxDisk)/1024/1024/1024)
	if d.MaxDisk > 0 {
		detail.DiskPercent = int((float64(d.Disk) / float64(d.MaxDisk)) * 100)
	}
	detail.Type = pveType

	// Config
	urlConfig := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/config", baseURL, targetNode, pveType, vmid)
	reqConfig, _ := http.NewRequest("GET", urlConfig, nil)
	headers(reqConfig)
	if respConfig, err := client.Do(reqConfig); err == nil && respConfig.StatusCode == 200 {
		defer respConfig.Body.Close()
		var configResp models.PveGuestConfigResponse
		if err := json.NewDecoder(respConfig.Body).Decode(&configResp); err == nil {
			if configResp.Data.Description != "" {
				detail.Note = configResp.Data.Description
			}
			if detail.Name == "" {
				if configResp.Data.Name != "" {
					detail.Name = configResp.Data.Name
				} else {
					detail.Name = configResp.Data.Hostname
				}
			}
			if detail.Cores == 0 && configResp.Data.Cores > 0 {
				detail.Cores = configResp.Data.Cores
			}
		}
	}

	return detail, nil
}

// FetchSyslog fetches syslog entries from the Proxmox node.
func (p *ProxmoxService) FetchSyslog(proxmoxURL, node, tokenID, tokenSecret string, start, limit int) []ProxmoxSyslogEntry {
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
		Timeout:   10 * time.Second,
	}
	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/syslog?start=%d&limit=%d", proxmoxURL, node, start, limit)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Data []ProxmoxSyslogEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	return result.Data
}

// ProxmoxSyslogEntry is a single Proxmox syslog line.
type ProxmoxSyslogEntry struct {
	N int    `json:"n"`
	T string `json:"t"`
}

// PowerAction sends a power action (start, stop, reboot, shutdown) to a VM/CT.
func (p *ProxmoxService) PowerAction(rawURL, configuredNode, tokenID, secret, pveType, vmid, action string) error {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	addAuth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// Auto-discover node
	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	addAuth(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/status/%s", baseURL, targetNode, pveType, vmid, action)
	req, _ := http.NewRequest("POST", apiURL, nil)
	addAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListSnapshots fetches the list of snapshots for a VM/CT.
func (p *ProxmoxService) ListSnapshots(rawURL, configuredNode, tokenID, secret, pveType, vmid string) ([]models.Snapshot, error) {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	addAuth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// Auto-discover node
	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	addAuth(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/snapshot", baseURL, targetNode, pveType, vmid)
	req, _ := http.NewRequest("GET", apiURL, nil)
	addAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var snapList models.PveSnapshotList
	if err := json.NewDecoder(resp.Body).Decode(&snapList); err != nil {
		return nil, err
	}

	var snapshots []models.Snapshot
	for _, s := range snapList.Data {
		if s.Name == "current" {
			continue
		}
		snapshots = append(snapshots, models.Snapshot{
			Name:        s.Name,
			Description: s.Description,
			SnapTime:    s.SnapTime,
			Parent:      s.Parent,
			Running:     s.Running == 1,
		})
	}

	return snapshots, nil
}

// CreateSnapshot creates a new snapshot for a VM/CT.
func (p *ProxmoxService) CreateSnapshot(rawURL, configuredNode, tokenID, secret, pveType, vmid, snapName, description string) error {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	addAuth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// Auto-discover node
	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	addAuth(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	formData := url.Values{}
	formData.Set("snapname", snapName)
	formData.Set("description", description)

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/snapshot", baseURL, targetNode, pveType, vmid)
	req, _ := http.NewRequest("POST", apiURL, strings.NewReader(formData.Encode()))
	addAuth(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteSnapshot deletes a snapshot from a VM/CT.
func (p *ProxmoxService) DeleteSnapshot(rawURL, configuredNode, tokenID, secret, pveType, vmid, snapName string) error {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	addAuth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// Auto-discover node
	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	addAuth(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/snapshot/%s", baseURL, targetNode, pveType, vmid, snapName)
	req, _ := http.NewRequest("DELETE", apiURL, nil)
	addAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RollbackSnapshot rolls back a VM/CT to a specific snapshot.
func (p *ProxmoxService) RollbackSnapshot(rawURL, configuredNode, tokenID, secret, pveType, vmid, snapName string) error {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	addAuth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// Auto-discover node
	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	addAuth(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/snapshot/%s/rollback", baseURL, targetNode, pveType, vmid, snapName)
	req, _ := http.NewRequest("POST", apiURL, nil)
	addAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreateVM creates a new QEMU VM on the Proxmox node. storage and bridge may be
// empty, in which case they are auto-detected from the Proxmox API.
func (p *ProxmoxService) CreateVM(rawURL, configuredNode, tokenID, secret string, vmid int, name string, cores int, memory int, diskSize int, storage, bridge string) error {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	addAuth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	addAuth(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	// Resolve storage/bridge: explicit config wins, otherwise auto-detect.
	if storage == "" {
		storage = p.detectStorage(client, baseURL, targetNode, tokenID, secret, "images")
	}
	if bridge == "" {
		bridge = p.detectBridge(client, baseURL, targetNode, tokenID, secret)
	}

	// Build form body
	form := url.Values{}
	form.Set("vmid", fmt.Sprintf("%d", vmid))
	form.Set("name", name)
	form.Set("cores", fmt.Sprintf("%d", cores))
	form.Set("memory", fmt.Sprintf("%d", memory))
	form.Set("scsi0", fmt.Sprintf("%s:%d", storage, diskSize))
	form.Set("net0", fmt.Sprintf("virtio,bridge=%s", bridge))
	form.Set("ostype", "l26")

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/qemu", baseURL, targetNode)
	req, _ := http.NewRequest("POST", apiURL, strings.NewReader(form.Encode()))
	addAuth(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// CreateCT creates a new LXC container on the Proxmox node. storage and bridge
// may be empty, in which case they are auto-detected from the Proxmox API.
func (p *ProxmoxService) CreateCT(rawURL, configuredNode, tokenID, secret string, vmid int, hostname string, cores int, memory int, diskSize int, template, storage, bridge string) error {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	addAuth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	addAuth(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	// Resolve storage/bridge: explicit config wins, otherwise auto-detect. CT
	// rootfs needs a storage that supports container volumes ("rootdir").
	if storage == "" {
		storage = p.detectStorage(client, baseURL, targetNode, tokenID, secret, "rootdir")
	}
	if bridge == "" {
		bridge = p.detectBridge(client, baseURL, targetNode, tokenID, secret)
	}

	form := url.Values{}
	form.Set("vmid", fmt.Sprintf("%d", vmid))
	form.Set("hostname", hostname)
	form.Set("cores", fmt.Sprintf("%d", cores))
	form.Set("memory", fmt.Sprintf("%d", memory))
	form.Set("rootfs", fmt.Sprintf("%s:%d", storage, diskSize))
	form.Set("net0", fmt.Sprintf("name=eth0,bridge=%s,ip=dhcp", bridge))
	if template != "" {
		form.Set("ostemplate", template)
	}

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/lxc", baseURL, targetNode)
	req, _ := http.NewRequest("POST", apiURL, strings.NewReader(form.Encode()))
	addAuth(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// detectStorage returns the first active storage on the node whose content
// list includes wantContent ("images" for VM disks, "rootdir" for CT rootfs).
// On any failure it falls back to "local-lvm" with a warning so guest creation
// still proceeds on a default Proxmox layout.
func (p *ProxmoxService) detectStorage(client *http.Client, baseURL, node, tokenID, secret, wantContent string) string {
	const fallback = "local-lvm"

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/storage", baseURL, node)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		slog.Warn("storage auto-detect: request build failed, using fallback", "fallback", fallback, "error", err)
		return fallback
	}
	req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("storage auto-detect: API call failed, using fallback", "fallback", fallback, "error", err)
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		slog.Warn("storage auto-detect: unexpected status, using fallback", "fallback", fallback, "status", resp.StatusCode)
		return fallback
	}

	var list models.PveStorageList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		slog.Warn("storage auto-detect: decode failed, using fallback", "fallback", fallback, "error", err)
		return fallback
	}

	for _, s := range list.Data {
		if s.Active == 0 || s.Enabled == 0 || s.Storage == "" {
			continue
		}
		for _, c := range strings.Split(s.Content, ",") {
			if strings.TrimSpace(c) == wantContent {
				slog.Info("storage auto-detected", "node", node, "storage", s.Storage, "content", wantContent)
				return s.Storage
			}
		}
	}

	slog.Warn("storage auto-detect: no matching active storage, using fallback", "fallback", fallback, "content", wantContent)
	return fallback
}

// detectBridge returns the first Linux bridge interface on the node. On any
// failure it falls back to "vmbr0" with a warning.
func (p *ProxmoxService) detectBridge(client *http.Client, baseURL, node, tokenID, secret string) string {
	const fallback = "vmbr0"

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/network?type=bridge", baseURL, node)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		slog.Warn("bridge auto-detect: request build failed, using fallback", "fallback", fallback, "error", err)
		return fallback
	}
	req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("bridge auto-detect: API call failed, using fallback", "fallback", fallback, "error", err)
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		slog.Warn("bridge auto-detect: unexpected status, using fallback", "fallback", fallback, "status", resp.StatusCode)
		return fallback
	}

	var list models.PveNetworkList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		slog.Warn("bridge auto-detect: decode failed, using fallback", "fallback", fallback, "error", err)
		return fallback
	}

	for _, n := range list.Data {
		// Guard on type too: some Proxmox versions ignore the ?type= filter.
		if n.Type == "bridge" && n.Iface != "" {
			slog.Info("bridge auto-detected", "node", node, "bridge", n.Iface)
			return n.Iface
		}
	}

	slog.Warn("bridge auto-detect: no bridge found, using fallback", "fallback", fallback)
	return fallback
}

// resolveRestoreStorage resolves the Proxmox storage a restore-test guest is
// restored into, applying the SINGLE resolution order used everywhere in Jalon 2:
//
//	override (extra_json['restore_storage'] OR pm.Storage)  — already merged into the
//	  ProxmoxConn snapshot before it reaches here (DB row > env layer)
//	> auto-detection (detectStorage, fail-soft: content "images" for qemu, "rootdir"
//	  for lxc — the same call CreateVM/CreateCT use)
//	> defaultRestoreStorage  — the ONE literal of last resort
//
// pveType is "qemu" or "lxc"; anything else is treated as qemu (VM disks). The
// auto-detection step never errors out: detectStorage already falls back internally
// on any API failure, so this method always returns a non-empty storage name and a
// down Proxmox simply yields the literal — restore is then attempted on a sane
// default rather than refused. It is read-only (a couple of GETs).
func (p *ProxmoxService) resolveRestoreStorage(pm config.ProxmoxConn, pveType string) string {
	// 1+2. Explicit override wins: a dedicated restore_storage, else the creation
	// storage already carried in the snapshot (DB extra_json or env, merged upstream).
	if pm.RestoreStorage != "" {
		return pm.RestoreStorage
	}
	if pm.Storage != "" {
		return pm.Storage
	}

	// 3. Auto-detect against the live node (fail-soft inside detectStorage). CT
	// rootfs needs a storage that supports container volumes ("rootdir").
	wantContent := "images"
	if pveType == "lxc" {
		wantContent = "rootdir"
	}
	client, baseURL, node := p.restoreClient(pm.URL, pm.Node, pm.TokenID, pm.TokenSecret, 10*time.Second)
	detected := p.detectStorage(client, baseURL, node, pm.TokenID, pm.TokenSecret, wantContent)
	if detected != "" {
		return detected
	}

	// 4. Last resort (detectStorage already returns its own "local-lvm" fallback on
	// failure, so this is belt-and-suspenders for an empty return).
	return defaultRestoreStorage
}

// getGuestIP fetches the IP address of a running VM/CT.
func (p *ProxmoxService) getGuestIP(client *http.Client, baseURL, node, tokenID, secret, kind string, id int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var apiURL string
	if kind == "CT" {
		apiURL = fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/interfaces", baseURL, node, id)
	} else if kind == "VM" {
		apiURL = fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", baseURL, node, id)
	} else {
		return "", nil
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil
	}

	if kind == "CT" {
		var lxcResp models.PveLxcInterfacesResponse
		if err := json.NewDecoder(resp.Body).Decode(&lxcResp); err != nil {
			return "", err
		}
		for _, iface := range lxcResp.Data {
			if iface.Name != "lo" && iface.Inet != "" && iface.Inet != "127.0.0.1" {
				parts := strings.Split(iface.Inet, "/")
				if len(parts) > 0 {
					return parts[0], nil
				}
			}
		}
	} else if kind == "VM" {
		var qemuResp models.PveQemuInterfacesResponse
		if err := json.NewDecoder(resp.Body).Decode(&qemuResp); err != nil {
			return "", err
		}
		for _, iface := range qemuResp.Data.Result {
			if iface.Name != "lo" {
				for _, ip := range iface.IPAddresses {
					if ip.IPAddressType == "ipv4" && ip.IPAddress != "127.0.0.1" {
						return ip.IPAddress, nil
					}
				}
			}
		}
	}
	return "", nil
}
