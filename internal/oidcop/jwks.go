package oidcop

import (
	"encoding/json"

	"github.com/mackee/tanukirpc"
)

// jwksHandler implements GET /jwks: this target's published signing keys,
// straight from internal/keys.Set.JWKS. The path here must match whatever
// discoveryHandler publishes as jwks_uri (see router.go).
func jwksHandler(t *Target) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], _ struct{}) (json.RawMessage, error) {
		if err := t.configuredError("jwks"); err != nil {
			return nil, err
		}
		return json.RawMessage(t.keys.JWKS()), nil
	})
}
