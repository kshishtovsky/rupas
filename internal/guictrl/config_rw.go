// config_rw.go — reading the current config back into the Settings form.
package guictrl

import (
	"os"

	"github.com/rupas/rupas/internal/config"
)

// LoadConfig returns the endpoint form values + DPI flag from the config file
// so Settings can pre-fill after onboarding (GUI_DESIGN §6.3).
func (c *Controller) LoadConfig() (EndpointInput, error) {
	path := c.configPath()
	if _, err := os.Stat(path); err != nil {
		return EndpointInput{DPI: true}, nil // no file yet: defaults
	}
	cfg, err := config.Load(path)
	if err != nil {
		return EndpointInput{}, err
	}
	in := EndpointInput{DPI: cfg.Desync.Strategy != ""}
	if cfg.Tunnels != nil && cfg.Tunnels.TCP != nil {
		ep := cfg.Tunnels.TCP
		in.Host = ep.Host
		in.Port = int(ep.Port)
		in.UUID = ep.UUID
		in.SNI = ep.SNI
		in.PBK = ep.RealityPBK
		in.SID = ep.RealitySID
	}
	return in, nil
}

func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "rupas-gui.exe"
	}
	return exe
}
