package httpx

import "github.com/mackee/tanukirpc"

// NewRouter returns a *tanukirpc.Router[Reg] already wired with this
// package's Codec and ErrorHooker, so that internal/oidcop cannot forget to
// install either. Extra opts are applied after the defaults, so a caller
// may still override the codec or hooker (e.g. in a test) if it needs to.
func NewRouter[Reg any](reg Reg, opts ...tanukirpc.RouterOption[Reg]) *tanukirpc.Router[Reg] {
	defaults := []tanukirpc.RouterOption[Reg]{
		tanukirpc.WithCodec[Reg](NewCodec()),
		tanukirpc.WithErrorHooker[Reg](NewErrorHooker()),
	}
	return tanukirpc.NewRouter(reg, append(defaults, opts...)...)
}
