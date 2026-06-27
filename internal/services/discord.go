package services

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/bwmarrin/discordgo"
)

// neutralizeDiscord defuses user-controlled text before it is embedded in a
// Discord message. It strips backticks (which would break out of code spans /
// fences) and disarms mentions (@everyone, @here, <@id>, <@&role>) by inserting a
// zero-width space after each "@", so the client no longer parses them as pings.
func neutralizeDiscord(s string) string {
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "@", "@​")
	return s
}

// DiscordBot wraps a discordgo session for sending alerts.
//
// token is retained ONLY so the registry's hot-reload (ApplyDiscord) can detect a
// token change for its no-op short-circuit; it is never logged, echoed, or sent to a
// template. The struct is immutable after NewDiscordBot, so the whole *DiscordBot is
// swapped on a reload (never a field), and every Send*/IsReady nil-guards on the
// session — so no per-send lock is needed.
type DiscordBot struct {
	session          *discordgo.Session
	token            string
	channelID        string
	authChannelID    string
	ansibleChannelID string
}

// NewDiscordBot creates and opens a new Discord bot session.
func NewDiscordBot(token, channelID, authChannelID, ansibleChannelID string) (*DiscordBot, error) {
	if token == "" || channelID == "" {
		return nil, fmt.Errorf("missing token or channel ID")
	}

	session, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, err
	}

	if err := session.Open(); err != nil {
		return nil, fmt.Errorf("error opening connection: %v", err)
	}

	slog.Info("Discord Bot is now running", "channel", channelID, "auth_channel", authChannelID, "ansible_channel", ansibleChannelID)
	return &DiscordBot{
		session:          session,
		token:            token,
		channelID:        channelID,
		authChannelID:    authChannelID,
		ansibleChannelID: ansibleChannelID,
	}, nil
}

// Close closes the Discord session.
func (d *DiscordBot) Close() {
	if d.session != nil {
		d.session.Close()
	}
}

// IsReady returns true if the Discord session is initialized.
func (d *DiscordBot) IsReady() bool {
	return d != nil && d.session != nil
}

// SendAlert sends a formatted SOAR alert embed to the main channel.
func (d *DiscordBot) SendAlert(title, message, severity string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}
	// title/message proviennent de Wazuh + sortie LLM (non fiables) → neutraliser
	// les mentions/markdown avant de les embarquer dans l'embed.
	title = neutralizeDiscord(title)
	message = neutralizeDiscord(message)

	color := 0x00ff00 // Green (Info)
	switch severity {
	case "critical":
		color = 0xff0000
	case "high":
		color = 0xffa500
	case "medium":
		color = 0xffff00
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🛡️ SOAR Alert: " + title,
		Description: message,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Security",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(d.channelID, embed)
	return err
}

// SendAnsibleAlert sends an Ansible scheduled playbook execution notification to the main channel.
func (d *DiscordBot) SendAnsibleAlert(playbook, vmName string, vmid int, status, output string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}
	// output (sortie brute du playbook) et vmName sont non fiables → neutraliser.
	playbook = neutralizeDiscord(playbook)
	vmName = neutralizeDiscord(vmName)
	output = neutralizeDiscord(output)

	color := 0x00ff00 // Green — success
	emoji := "✅"
	if status == "error" {
		color = 0xff0000
		emoji = "❌"
	}

	// Truncate output for Discord embed (max ~1000 chars)
	if len(output) > 1000 {
		output = output[len(output)-1000:]
	}

	description := fmt.Sprintf("**Playbook:** `%s`\n**Cible:** %s (%d)\n**Statut:** %s %s", playbook, vmName, vmid, emoji, status)
	if output != "" {
		description += fmt.Sprintf("\n\n```\n%s\n```", output)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "📋 Ansible: " + playbook,
		Description: description,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Ansible Scheduler",
		},
	}

	channelID := d.ansibleChannelID
	if channelID == "" {
		channelID = d.channelID
	}

	_, err := d.session.ChannelMessageSendEmbed(channelID, embed)
	return err
}

// SendBackupAlert sends a backup execution notification embed to the main channel.
// status: "started", "completed" or "failed".
func (d *DiscordBot) SendBackupAlert(target string, vmid int, backupType, status, details string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}

	color := 0x808080 // Grey — started
	emoji := "⏳"
	switch status {
	case "completed":
		color = 0x00ff00 // Green — success
		emoji = "✅"
	case "failed":
		color = 0xff0000 // Red — failure
		emoji = "❌"
	}

	// Neutralize untrusted fields (target name comes from Proxmox guest config,
	// details may embed a Proxmox API error message) before building Markdown.
	target = neutralizeDiscord(target)
	details = neutralizeDiscord(details)

	// Truncate details for Discord embed.
	if len(details) > 1000 {
		details = details[len(details)-1000:]
	}

	description := fmt.Sprintf("**Cible:** %s (%d)\n**Type:** `%s`\n**Statut:** %s %s", target, vmid, backupType, emoji, status)
	if details != "" {
		description += fmt.Sprintf("\n\n```\n%s\n```", details)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "📦 Backup: " + target,
		Description: description,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Backup",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(d.channelID, embed)
	return err
}

// SendRestoreTestAlert sends a restore-test verdict embed to the main channel.
// verdict: "passed" or "failed" (anything else renders as a neutral state).
func (d *DiscordBot) SendRestoreTestAlert(target string, vmid int, level, verdict string, rtoSec int, detail string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}

	color := 0x808080 // Grey — neutral / running
	emoji := "🧪"
	switch verdict {
	case "passed":
		color = 0x00ff00 // Green
		emoji = "✅"
	case "failed":
		color = 0xff0000 // Red
		emoji = "❌"
	}

	// Neutralize untrusted fields (target name from Proxmox guest config; detail
	// may embed a Proxmox API error message) before building Markdown.
	target = neutralizeDiscord(target)
	detail = neutralizeDiscord(detail)
	if len(detail) > 1000 {
		detail = detail[len(detail)-1000:]
	}

	description := fmt.Sprintf("**Cible:** %s\n**Niveau:** `%s`\n**Verdict:** %s %s", target, level, emoji, verdict)
	if vmid > 0 {
		description += fmt.Sprintf("\n**Sandbox VMID:** `%d`", vmid)
	}
	if rtoSec > 0 {
		description += fmt.Sprintf("\n**RTO:** %ds", rtoSec)
	}
	if detail != "" {
		description += fmt.Sprintf("\n\n```\n%s\n```", detail)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🧪 Test de restauration: " + target,
		Description: description,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Restore Test",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(d.channelID, embed)
	return err
}

// SendZombieSandboxAlert warns that a disposable restore-test sandbox guest could
// not be destroyed and is now leaking on the host — a human must intervene before
// it accumulates and fills the disk. vmid is always in the sandbox range.
func (d *DiscordBot) SendZombieSandboxAlert(vmid int, detail string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}

	// detail may embed a Proxmox API error message — neutralize before Markdown.
	detail = neutralizeDiscord(detail)
	if len(detail) > 1000 {
		detail = detail[len(detail)-1000:]
	}

	description := fmt.Sprintf(
		"⚠️ Le sandbox de test de restauration **VMID `%d`** n'a pas pu être détruit.\n"+
			"Intervention manuelle requise (ce guest jetable consomme du disque).", vmid)
	if detail != "" {
		description += fmt.Sprintf("\n\n```\n%s\n```", detail)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🧟 Sandbox zombie non détruit",
		Description: description,
		Color:       0xff0000, // Red — needs intervention
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Restore Test",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(d.channelID, embed)
	return err
}

// SendAuthAlert sends an authentication alert to the dedicated auth channel (or main channel as fallback).
func (d *DiscordBot) SendAuthAlert(title, message string, blocked bool) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}
	// message contient le nom d'utilisateur d'une tentative de login (fourni par un
	// client NON authentifié) → neutraliser les mentions/markdown (anti @everyone).
	title = neutralizeDiscord(title)
	message = neutralizeDiscord(message)

	channelID := d.authChannelID
	if channelID == "" {
		channelID = d.channelID
	}

	color := 0xffa500 // Orange — single failure
	if blocked {
		color = 0xff0000 // Red — IP blocked
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🔐 Auth: " + title,
		Description: message,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Auth Monitor",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(channelID, embed)
	return err
}
