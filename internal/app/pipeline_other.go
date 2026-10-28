//go:build !windows

package app

import (
	"errors"
	"log"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/supervisor"
)

// unsupportedPipeline keeps non-Windows builds compiling: the capture
// engine is WinDivert-based and cannot run there. Start reports that
// honestly instead of pretending interception works.
type unsupportedPipeline struct{}

var (
	_ supervisor.Pipeline = unsupportedPipeline{}
	_ pipelineControl     = unsupportedPipeline{}
)

func newPipeline(pipelineDeps) pipelineControl { return unsupportedPipeline{} }

func (unsupportedPipeline) Start(*config.Config) error {
	return errors.New("app: capture engine requires Windows (WinDivert)")
}
func (unsupportedPipeline) Stop() error                                        { return nil }
func (unsupportedPipeline) SuspendForProbe() suspendToken                      { return suspendToken{} }
func (unsupportedPipeline) ResumeFromProbe(suspendToken, *config.DesyncParams) {}
func (unsupportedPipeline) TunnelHealth() (assembled, healthy bool)            { return false, false }
func (unsupportedPipeline) Stats() pipelineStats                               { return pipelineStats{} }
func (unsupportedPipeline) SetDegradationSink(func(string))                    {}
