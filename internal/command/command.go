package command

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

type envContextKey struct{}

type TimeoutError struct {
	Name    string
	Args    []string
	Timeout time.Duration
}

type Runner interface {
	CombinedOutput(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

var DefaultRunner Runner = ExecRunner{}

func (e TimeoutError) Error() string {
	return e.Name + " " + strings.Join(e.Args, " ") + " timed out after " + e.Timeout.String()
}

func IsTimeout(err error) bool {
	var timeoutErr TimeoutError
	return errors.As(err, &timeoutErr)
}

func WithEnv(ctx context.Context, env ...string) context.Context {
	if len(env) == 0 {
		return ctx
	}
	merged := append([]string(nil), Env(ctx)...)
	merged = append(merged, env...)
	return context.WithValue(ctx, envContextKey{}, merged)
}

func Env(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	env, _ := ctx.Value(envContextKey{}).([]string)
	return env
}

func CombinedOutput(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) ([]byte, error) {
	return DefaultRunner.CombinedOutput(ctx, dir, timeout, name, args...)
}

func Output(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) ([]byte, []byte, error) {
	stdout, stderr, err := run(ctx, dir, timeout, name, args...)
	return stdout, stderr, err
}

func (ExecRunner) CombinedOutput(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) ([]byte, error) {
	stdout, stderr, err := run(ctx, dir, timeout, name, args...)
	return append(stdout, stderr...), err
}

func run(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) ([]byte, []byte, error) {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Dir = dir
	if env := Env(cctx); len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	configureProcessTree(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return stdout.Bytes(), stderr.Bytes(), err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if cctx.Err() != nil {
			return stdout.Bytes(), stderr.Bytes(), TimeoutError{Name: name, Args: append([]string(nil), args...), Timeout: timeout}
		}
		return stdout.Bytes(), stderr.Bytes(), err
	case <-cctx.Done():
		terminateProcessTree(cmd)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		return stdout.Bytes(), stderr.Bytes(), TimeoutError{Name: name, Args: append([]string(nil), args...), Timeout: timeout}
	}
}
