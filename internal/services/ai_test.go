package services

import "testing"

func TestCleanAIResponse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "strips think block and keeps analysis",
			in:   "<think>raisonnement interne</think>\n**Analyse:** Tout va bien",
			want: "**Analyse:** Tout va bien",
		},
		{
			name: "uses last closing think tag",
			in:   "<think>a</think> bruit <think>b</think>**Analyse:** ok",
			want: "**Analyse:** ok",
		},
		{
			name: "keeps only content after the closing think tag",
			in:   "avant <think>caché</think> après",
			want: "après",
		},
		{
			name: "removes unterminated-pair think when no closing tag at end",
			in:   "<think>caché</think>texte visible",
			want: "texte visible",
		},
		{
			name: "trims surrounding whitespace",
			in:   "   réponse simple   ",
			want: "réponse simple",
		},
		{
			name: "passthrough when no markers",
			in:   "réponse directe",
			want: "réponse directe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanAIResponse(tt.in); got != tt.want {
				t.Errorf("cleanAIResponse() = %q, want %q", got, tt.want)
			}
		})
	}
}
