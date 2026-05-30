package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	ExitSuccess       = 0
	ExitPolicyFailure = 1
	ExitUsage         = 2
	ExitConfig        = 3
	ExitAnalysis      = 4
	ExitProvider      = 5
	ExitPrivacy       = 6
	ExitInternal      = 7
)

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	switch e.code {
	case ExitPolicyFailure:
		return "trustmod policy recommendation failed"
	case ExitUsage:
		return "usage error"
	case ExitConfig:
		return "invalid config or policy"
	case ExitAnalysis:
		return "analysis failed"
	case ExitProvider:
		return "data provider failure in --strict-data mode"
	case ExitPrivacy:
		return "privacy violation prevented remote query"
	default:
		return "internal error"
	}
}

func (e exitError) Unwrap() error {
	return e.err
}

func ExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	if isUsageError(err) {
		return ExitUsage
	}
	return ExitInternal
}

func policyExitError() error {
	return exitError{code: ExitPolicyFailure}
}

func usageExitError(err error) error {
	return exitError{code: ExitUsage, err: err}
}

func userFileExitError(err error) error {
	if err == nil {
		err = os.ErrInvalid
	}
	return exitError{code: ExitUsage, err: err}
}

func readUserFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, userFileExitError(err)
	}
	return data, nil
}

func configExitError(err error) error {
	return exitError{code: ExitConfig, err: err}
}

func analysisExitError(err error) error {
	return exitError{code: ExitAnalysis, err: err}
}

func providerExitError(err error) error {
	if err == nil {
		err = fmt.Errorf("data provider failure in --strict-data mode")
	}
	return exitError{code: ExitProvider, err: err}
}

func isUsageError(err error) bool {
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	for _, prefix := range []string{
		"accepts ",
		"requires ",
		"unknown command",
		"unknown flag",
		"invalid argument",
		"flag needs an argument",
		"required flag",
	} {
		if strings.HasPrefix(msg, prefix) {
			return true
		}
	}
	return strings.Contains(msg, "unknown shorthand flag")
}
