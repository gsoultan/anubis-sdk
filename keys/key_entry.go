package keys

type Entry struct {
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`        // "Ed25519"
	PublicKey string `json:"public_key"` // base64url, 32 bytes
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
}
