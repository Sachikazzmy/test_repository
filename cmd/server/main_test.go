package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"bannerfingerprint/internal/config"
)

var discardLogger = log.New(io.Discard, "", 0)

type observedListener struct {
	net.Listener
	ready, closed        chan struct{}
	readyOnce, closeOnce sync.Once
}

func (l *observedListener) Accept() (net.Conn, error) {
	l.readyOnce.Do(func() { close(l.ready) })
	return l.Listener.Accept()
}
func (l *observedListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.closed) })
	return err
}

type runningServer struct {
	listener *observedListener
	cancel   context.CancelFunc
	done     chan struct{}
	err      error
}

func waitFor(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for lifecycle event")
	}
}
func startServer(t *testing.T, cfg config.Config, h http.Handler) *runningServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runningServer{listener: &observedListener{Listener: ln, ready: make(chan struct{}), closed: make(chan struct{})}, cancel: cancel, done: make(chan struct{})}
	go func() { r.err = serve(ctx, cfg, r.listener, h, discardLogger); close(r.done) }()
	t.Cleanup(func() { cancel(); waitFor(t, r.done) })
	waitFor(t, r.listener.ready)
	return r
}
func assertPortReleased(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listener not released: %v", err)
	}
	_ = ln.Close()
}

type requestOutcome struct {
	status int
	err    error
}

func startRequest(t *testing.T, addr string) <-chan requestOutcome {
	t.Helper()
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	done := make(chan requestOutcome, 1)
	go func() {
		response, err := client.Get("http://" + addr + "/healthz")
		outcome := requestOutcome{err: err}
		if err == nil {
			outcome.status = response.StatusCode
			_, outcome.err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		done <- outcome
	}()
	return done
}
func requestResult(t *testing.T, ch <-chan requestOutcome) requestOutcome {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("request did not exit")
		return requestOutcome{}
	}
}

func TestGracefulShutdownWaitsForActiveRequest(t *testing.T) {
	entered, finished := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	releaseRequest := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseRequest)
	var requestCtx context.Context
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		requestCtx = r.Context()
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := config.Default()
	cfg.ShutdownTimeout = time.Second
	running := startServer(t, cfg, h)
	// Release before startServer's cleanup waits if an assertion fails.
	t.Cleanup(releaseRequest)
	request := startRequest(t, running.listener.Addr().String())
	waitFor(t, entered)
	running.cancel()
	waitFor(t, running.listener.closed)
	if requestCtx.Err() != nil {
		t.Fatal("shutdown canceled an active request before grace elapsed")
	}
	select {
	case <-running.done:
		t.Fatal("shutdown returned before handler completed")
	default:
	}
	releaseRequest()
	outcome := requestResult(t, request)
	if outcome.err != nil || outcome.status != 204 {
		t.Fatalf("request: %+v", outcome)
	}
	waitFor(t, finished)
	waitFor(t, running.done)
	if running.err != nil {
		t.Fatal(running.err)
	}
	assertPortReleased(t, running.listener.Addr().String())
}

func TestShutdownDeadlineClosesConnectionAndCancelsRequest(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(exited) })
	cfg := config.Default()
	cfg.ShutdownTimeout = 30 * time.Millisecond
	running := startServer(t, cfg, h)
	request := startRequest(t, running.listener.Addr().String())
	waitFor(t, entered)
	running.cancel()
	waitFor(t, running.done)
	waitFor(t, exited)
	if !errors.Is(running.err, context.DeadlineExceeded) {
		t.Fatalf("expected shutdown deadline, got %v", running.err)
	}
	if outcome := requestResult(t, request); outcome.err == nil {
		t.Fatal("expected forced connection close")
	}
	assertPortReleased(t, running.listener.Addr().String())
}

func TestShutdownWithoutRequestsReleasesListener(t *testing.T) {
	running := startServer(t, config.Default(), http.NotFoundHandler())
	running.cancel()
	waitFor(t, running.done)
	if running.err != nil {
		t.Fatal(running.err)
	}
	assertPortReleased(t, running.listener.Addr().String())
}

func TestRunStartupFailures(t *testing.T) {
	cfg := config.Default()
	cfg.Service.Workers = 0
	if err := run(context.Background(), cfg, discardLogger); err == nil {
		t.Fatal("invalid config accepted")
	}
	cfg = config.Default()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, cfg, discardLogger); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg.ListenAddr = ln.Addr().String()
	if err := run(context.Background(), cfg, discardLogger); err == nil {
		t.Fatal("bind conflict accepted")
	}
	// An externally closed listener must surface a Serve error and release resources.
	_ = ln.Close()
	if err := serve(context.Background(), cfg, ln, http.NotFoundHandler(), discardLogger); err == nil {
		t.Fatal("Serve failure hidden")
	}
}

func TestHTTPServerTimeoutConfiguration(t *testing.T) {
	cfg := config.Default()
	cfg.ReadHeaderTimeout = 2 * time.Second
	cfg.WriteTimeout = 25 * time.Second
	cfg.IdleTimeout = 30 * time.Second
	handler := http.NewServeMux()
	server := newHTTPServer(cfg, handler, discardLogger)
	if server.Handler != handler || server.ReadHeaderTimeout != cfg.ReadHeaderTimeout || server.WriteTimeout != cfg.WriteTimeout || server.IdleTimeout != cfg.IdleTimeout || server.ErrorLog != discardLogger {
		t.Fatalf("server configuration drift: %+v", server)
	}
}

// Run the real entry path in a child test process so OS signals cannot
// interrupt the parent test runner. All sockets are bound to loopback only.
func TestServerProcess(t *testing.T) {
	if os.Getenv("BANNER_TEST_SERVER_PROCESS") != "1" {
		return
	}
	if err := execute(log.New(os.Stdout, "", 0)); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSignalsStopRealServer(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestServerProcess$")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "BANNER_") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "BANNER_TEST_SERVER_PROCESS=1", "BANNER_LISTEN_ADDR=127.0.0.1:0", "BANNER_SHUTDOWN_TIMEOUT=1s")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var processErr error
			go func() { processErr = cmd.Wait(); close(done) }()
			t.Cleanup(func() { _ = cmd.Process.Kill(); waitFor(t, done) })
			ready := make(chan string, 1)
			scanned := make(chan struct{})
			go func() {
				defer close(scanned)
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					if addr, ok := strings.CutPrefix(scanner.Text(), "服务监听 "); ok {
						ready <- addr
					}
				}
			}()
			var addr string
			select {
			case addr = <-ready:
			case <-done:
				t.Fatalf("server exited before startup: %v", processErr)
			case <-time.After(5 * time.Second):
				t.Fatal("server did not start")
			}
			outcome := requestResult(t, startRequest(t, addr))
			if outcome.err != nil || outcome.status != http.StatusOK {
				t.Fatalf("real server health: %+v", outcome)
			}
			if err = cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			waitFor(t, done)
			waitFor(t, scanned)
			if processErr != nil {
				t.Fatalf("signal exit: %v", processErr)
			}
			assertPortReleased(t, addr)
		})
	}
}
