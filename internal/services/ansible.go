package services

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// remoteUserPattern restricts the SSH user to safe characters to prevent
// command/argument injection via the --user flag.
var remoteUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidRemoteUser reports whether user is a safe, non-empty SSH login name. It is
// the single source of truth reused by the handlers (reject at the HTTP boundary
// with a 400) and by RunPlaybook (reject before shelling out to ansible-playbook).
func ValidRemoteUser(user string) bool {
	return remoteUserPattern.MatchString(user)
}

// ListPlaybooks scans the given directory and returns a map of categories to playbook files.
func ListPlaybooks(dir string) (map[string][]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}
		return nil, err
	}

	playbooks := make(map[string][]string)
	playbooks["Général"] = []string{}

	for _, e := range entries {
		if e.IsDir() {
			subEntries, err := os.ReadDir(dir + "/" + e.Name())
			if err == nil {
				var subList []string
				for _, sub := range subEntries {
					if !sub.IsDir() && (strings.HasSuffix(sub.Name(), ".yml") || strings.HasSuffix(sub.Name(), ".yaml")) {
						subList = append(subList, e.Name()+"/"+sub.Name())
					}
				}
				if len(subList) > 0 {
					playbooks[e.Name()] = subList
				}
			}
		} else if strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml") {
			playbooks["Général"] = append(playbooks["Général"], e.Name())
		}
	}

	if len(playbooks["Général"]) == 0 {
		delete(playbooks, "Général")
	}

	return playbooks, nil
}

// RunPlaybook executes an ansible-playbook command and returns a streaming reader.
// The caller MUST call the returned cleanup function after consuming all output.
// cleanup waits for the process to exit, removes the temp key, and RETURNS the
// playbook's exit error (nil on success, *exec.ExitError on a non-zero exit) — so the
// caller can base success/failure on the real exit code rather than on fragile
// string-matching of the output. cleanup is idempotent (safe to call more than once).
//
// remoteUser is REQUIRED (no 'root' fallback): root SSH is disabled fleet-wide
// (PermitRootLogin=no), so a run must always target an explicit, non-root user.
// When become is true, --become is appended so privileged tasks escalate via sudo
// instead of needing a root login.
func RunPlaybook(playbookPath string, targetIP string, privateKey string, remoteUser string, become bool) (io.ReadCloser, func() error, error) {
	// Validate IP to prevent command injection via inventory parameter
	if ip := net.ParseIP(targetIP); ip == nil {
		return nil, nil, fmt.Errorf("invalid target IP address: %s", targetIP)
	}

	// remote_user is mandatory and validated to prevent injection. No silent 'root'
	// fallback: an empty user is a caller bug (handlers/worker enforce it earlier).
	if remoteUser == "" {
		return nil, nil, fmt.Errorf("remote user is required")
	}
	if !ValidRemoteUser(remoteUser) {
		return nil, nil, fmt.Errorf("invalid remote user: %s", remoteUser)
	}

	tmpKey, err := os.CreateTemp("", "ansible-key-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp key: %v", err)
	}
	tmpKeyName := tmpKey.Name()

	if err := os.Chmod(tmpKeyName, 0600); err != nil {
		os.Remove(tmpKeyName)
		return nil, nil, fmt.Errorf("failed to chmod temp key: %v", err)
	}
	if _, err := tmpKey.WriteString(privateKey); err != nil {
		os.Remove(tmpKeyName)
		return nil, nil, fmt.Errorf("failed to write temp key: %v", err)
	}
	tmpKey.Close()

	args := []string{
		"-i", fmt.Sprintf("%s,", targetIP),
		playbookPath,
		"--private-key", tmpKeyName,
		"--user", remoteUser,
		"--ssh-common-args", "-o StrictHostKeyChecking=accept-new",
	}
	if become {
		// Privilege escalation via sudo for privileged tasks run by a non-root user.
		args = append(args, "--become")
	}
	cmd := exec.Command("ansible-playbook", args...)

	pr, pw, err := os.Pipe()
	if err != nil {
		os.Remove(tmpKeyName)
		return nil, nil, err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		os.Remove(tmpKeyName)
		return nil, nil, err
	}

	// La goroutine attend la fin du process, mémorise son code de sortie puis ferme le
	// pipe (EOF côté lecteur). `done` est fermé une fois waitErr écrit, ce qui rend
	// cleanup() sûr en appels multiples (lecture répétée d'un channel fermé).
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		pw.Close()
		close(done)
	}()

	// cleanup attend la fin du process, supprime la clé temporaire et renvoie l'erreur
	// de sortie réelle (nil si le playbook a réussi). Idempotent.
	cleanup := func() error {
		<-done
		os.Remove(tmpKeyName)
		return waitErr
	}

	return pr, cleanup, nil
}
