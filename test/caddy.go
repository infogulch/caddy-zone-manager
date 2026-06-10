package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// lockedBuffer is a concurrency-safe bytes.Buffer for capturing the Caddy
// process's stdout/stderr (written from the child, read on failure).
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// caddyProcess manages the Caddy process started by the harness.
type caddyProcess struct {
	bin       string
	adminAddr string
	cmd       *exec.Cmd
	output    lockedBuffer
	exited    chan struct{}
	waitErr   error
}

// startCaddy launches `caddy run --config <configPath>` and begins reaping it
// in the background. The Admin API address is taken from the config itself.
func startCaddy(bin, configPath, adminAddr string) (*caddyProcess, error) {
	p := &caddyProcess{
		bin:       bin,
		adminAddr: adminAddr,
		exited:    make(chan struct{}),
	}
	p.cmd = exec.Command(bin, "run", "--config", configPath)
	p.cmd.Stdout = &p.output
	p.cmd.Stderr = &p.output
	if err := p.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start caddy: %w", err)
	}
	go func() {
		p.waitErr = p.cmd.Wait()
		close(p.exited)
	}()
	return p, nil
}

// waitAdmin polls GET /config/ on the Admin API until it returns HTTP 200,
// the timeout elapses, the context is cancelled, or the process exits.
func (p *caddyProcess) waitAdmin(ctx context.Context, timeout time.Duration) error {
	url := "http://" + p.adminAddr + "/config/"
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	for {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-p.exited:
			return fmt.Errorf("caddy exited before admin API came up: %v\noutput: %s", p.waitErr, p.output.String())
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("admin API at %s not reachable after %s", p.adminAddr, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// reload applies a config via `caddy reload --config <path> --force --address
// <admin-addr>`, returning the command's combined output.
//
// The reload subcommand is used rather than SIGUSR1/SIGHUP because it is
// synchronous: it returns only after Caddy has accepted and provisioned the
// new config (or reported an error), which makes sequencing reliable.
// --force ensures byte-identical configs are still re-provisioned (without
// it Caddy short-circuits /load and emits no new sync, hanging every
// reload-the-identical-config idempotency case); --address targets the
// configured Admin API.
//
// Reload is NOT sync: the module's zone sync runs in a background goroutine
// spawned by Start() with exponential-backoff retry, so it may complete
// arbitrarily later. All post-reload assertions must poll with a deadline
// (see runner.go waitForSync and the log-offset attribution there).
func (p *caddyProcess) reload(ctx context.Context, configPath string) (string, error) {
	cmd := exec.CommandContext(ctx, p.bin, "reload", "--config", configPath, "--force", "--address", p.adminAddr)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// stop sends SIGTERM and waits up to 10 s for exit, escalating to SIGKILL.
func (p *caddyProcess) stop() error {
	if p.cmd.Process == nil {
		return nil
	}
	select {
	case <-p.exited:
		return nil // already gone
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		p.kill()
	}
	select {
	case <-p.exited:
		return nil
	case <-time.After(10 * time.Second):
		p.kill()
		<-p.exited
		return fmt.Errorf("caddy did not exit within 10s of SIGTERM; killed")
	}
}

// kill terminates the process immediately (used on a second interrupt).
func (p *caddyProcess) kill() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
}

// checkAdminAddrFree verifies nothing is already listening on the Admin API
// address: a refused TCP connection is the pass condition.
func checkAdminAddrFree(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("something is already listening on %s", addr)
	}
	return nil
}

// caddyVersion runs `caddy version` to verify the binary works.
func caddyVersion(ctx context.Context, bin string) (string, error) {
	out, err := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%q version: %v: %s", bin, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
