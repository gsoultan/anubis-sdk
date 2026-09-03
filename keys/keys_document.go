package keys

// Document is the shape served at /.well-known/anubis-keys.json.
type Document struct {
	Issuer string  `json:"issuer"`
	Keys   []Entry `json:"keys"`
}
