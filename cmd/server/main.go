package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"bannerfingerprint/internal/config"
	"bannerfingerprint/internal/fingerprint"
	"bannerfingerprint/internal/httpapi"
	"bannerfingerprint/internal/service"
)

func main() {
	logger := log.New(os.Stderr, "banner-server ", log.LstdFlags|log.LUTC)
	if err := execute(logger); err != nil {
		logger.Printf("服务退出：%v", err)
		os.Exit(1)
	}
}

func execute(logger *log.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("加载配置：%w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, cfg, logger)
}

func run(ctx context.Context, cfg config.Config, logger *log.Logger) error {
	if err := config.Validate(cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	recognizer, err := fingerprint.New()
	if err != nil {
		return fmt.Errorf("初始化规则：%w", err)
	}
	batch, err := service.New(recognizer, cfg.Service)
	if err != nil {
		return fmt.Errorf("初始化业务服务：%w", err)
	}
	handler, err := httpapi.New(batch, cfg.HTTP)
	if err != nil {
		return fmt.Errorf("初始化HTTP接口：%w", err)
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("绑定监听地址：%w", err)
	}
	return serve(ctx, cfg, listener, handler, logger)
}

func newHTTPServer(cfg config.Config, handler http.Handler, logger *log.Logger) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout, ErrorLog: logger,
	}
}

// serve owns listener. Active requests retain their contexts during graceful
// shutdown; Close cancels them if the independent shutdown deadline expires.
func serve(ctx context.Context, cfg config.Config, listener net.Listener, handler http.Handler, logger *log.Logger) error {
	server := newHTTPServer(cfg, handler, logger)
	defer server.Close()
	defer listener.Close()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	logger.Printf("服务监听 %s", listener.Addr())
	select {
	case err := <-done:
		return fmt.Errorf("HTTP服务停止：%w", err)
	case <-ctx.Done():
	}
	logger.Print("正在退出，等待在途请求")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		_ = server.Close()
	}
	serveErr := <-done
	if shutdownErr != nil {
		return fmt.Errorf("优雅退出未完成，已关闭连接：%w", shutdownErr)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("HTTP服务停止：%w", serveErr)
	}
	logger.Print("服务已退出")
	return nil
}
