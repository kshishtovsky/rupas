package android

// nopPlatform is the minimal adapter.PlatformInterface stub injected into
// the relay's sing-box context. Its only job is to be NON-nil: a nil
// platform interface on Android makes sing-box's network manager try to
// build its own PackageManager (reads /data/system/packages.xml — apps are
// not allowed) and crash later in that half-initialised path. Everything
// here answers "not supported" so sing-box falls back to neutral defaults;
// the actual VPN bypass is handled app-side (the package is a VpnService
// disallowed application).

import (
	"context"
	"errors"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing-tun"
)

// errNotSupported is the universal stub-platform answer: the stub exists
// only to keep sing-box off its self-managed Android integrations.
var errNotSupported = errors.New("not supported by rupas relay stub platform")

type nopPlatform struct{}

var _ adapter.PlatformInterface = nopPlatform{}

func (nopPlatform) Initialize(adapter.NetworkManager) error { return nil }

func (nopPlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (nopPlatform) AutoDetectInterfaceControl(int) error        { return errNotSupported }

func (nopPlatform) UsePlatformInterface() bool { return false }
func (nopPlatform) OpenInterface(*tun.Options, option.TunPlatformOptions) (tun.Tun, error) {
	return nil, errNotSupported
}
func (nopPlatform) ProcessPlatformOptions(option.TunPlatformOptions) error { return nil }

func (nopPlatform) UsePlatformDefaultInterfaceMonitor() bool             { return false }
func (nopPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}

func (nopPlatform) UsePlatformNetworkInterfaces() bool                     { return false }
func (nopPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, errNotSupported }

func (nopPlatform) UnderNetworkExtension() bool                { return false }
func (nopPlatform) NetworkExtensionIncludeAllNetworks() bool   { return false }
func (nopPlatform) ClearDNSCache()                             {}
func (nopPlatform) RequestPermissionForWIFIState() error       { return errNotSupported }
func (nopPlatform) ReadWIFIState(context.Context) adapter.WIFIState { return adapter.WIFIState{} }

func (nopPlatform) UsePlatformConnectionOwnerFinder() bool { return false }
func (nopPlatform) FindConnectionOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, errNotSupported
}

func (nopPlatform) UsePlatformWIFIMonitor() bool { return false }

func (nopPlatform) UsePlatformNotification() bool                        { return false }
func (nopPlatform) SendNotification(*adapter.Notification) error         { return errNotSupported }
func (nopPlatform) CancelNotification(string, int32) error               { return errNotSupported }

func (nopPlatform) MyInterfaceAddress() []netip.Addr { return nil }

func (nopPlatform) UsePlatformNeighborResolver() bool { return false }
func (nopPlatform) StartNeighborMonitor(adapter.NeighborUpdateListener) error { return errNotSupported }
func (nopPlatform) CloseNeighborMonitor(adapter.NeighborUpdateListener) error { return errNotSupported }

func (nopPlatform) UsePlatformShell() bool           { return false }
func (nopPlatform) CheckPlatformShell() error        { return errNotSupported }
func (nopPlatform) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, errNotSupported
}
func (nopPlatform) LookupUser(string) (*adapter.PlatformUser, error) { return nil, errNotSupported }
func (nopPlatform) LookupSFTPServer() (string, error)                { return "", errNotSupported }
func (nopPlatform) ReadSystemSSHHostKey() ([]byte, error)            { return nil, errNotSupported }
func (nopPlatform) TailscaleHostname() string                        { return "" }

func (nopPlatform) UsePlatformBridge() bool                          { return false }
func (nopPlatform) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, errNotSupported
}
