package services

import (
	"strings"
	"testing"
)

// TestNeutralizeDiscord verrouille la primitive anti-injection appliquée par SendAlert,
// SendAuthAlert, SendAnsibleAlert et SendBackupAlert sur tout texte non fiable (nom
// d'utilisateur d'un login échoué — fourni par un client NON authentifié —, sortie de
// playbook, alerte Wazuh, sortie LLM) avant l'embed Discord. Elle doit casser les
// mentions de masse (@everyone/@here) et neutraliser les code-spans (backticks).
func TestNeutralizeDiscord(t *testing.T) {
	// Les backticks sont retirés (sinon un texte hostile peut sortir d'un bloc de code
	// et réintroduire du markdown actif).
	if strings.Contains(neutralizeDiscord("x`y`z"), "`") {
		t.Fatal("neutralizeDiscord doit retirer les backticks")
	}

	// La mention de masse @everyone ne doit plus apparaître telle quelle (un séparateur
	// invisible est inséré juste après le @ pour la désamorcer sans la masquer).
	out := neutralizeDiscord("@everyone get pwned")
	if strings.Contains(out, "@everyone") {
		t.Fatalf("neutralizeDiscord doit casser @everyone, obtenu %q", out)
	}
	if !strings.Contains(out, "@​") {
		t.Fatal("neutralizeDiscord doit insérer un séparateur invisible (U+200B) après @")
	}

	// Un texte sans caractère dangereux reste lisible (pas de mutilation inutile).
	if got := neutralizeDiscord("OPNsense backup OK"); got != "OPNsense backup OK" {
		t.Fatalf("neutralizeDiscord altère un texte sûr: %q", got)
	}
}
