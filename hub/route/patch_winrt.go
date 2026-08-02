//go:build windows && cgo

package route

func init() {
	SetEmbedMode(true) // WinRT broker process: disallow restart/upgrade
}
