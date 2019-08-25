package blacklist

type (
	// Blacklist interface
	Blacklist interface {
		// Add token to blacklist
		Add(tokenID string) error
		// Exists function determines if token does exist in blacklist
		Exists(tokenID string) bool
	}
)
