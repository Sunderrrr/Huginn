// Command huginn-worker is the fleet worker daemon. Subcommands:
//
//	enroll        register this machine with the hub (used by install.sh)
//	run           run the agent loop (systemd ExecStart)
//	install-service  write and enable the systemd unit
//	healthcheck   exit 0 if this binary is runnable (used by self-update)
//	version       print the build version
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Sunderrrr/Huginn/worker/internal/agent"
	"github.com/Sunderrrr/Huginn/worker/internal/config"
	"github.com/Sunderrrr/Huginn/worker/internal/hubclient"
	"github.com/Sunderrrr/Huginn/worker/internal/systemd"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	stateDir := config.DefaultStateDir
	args := parseStateDir(os.Args[2:], &stateDir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(stateDir)
	case "run":
		err = cmdRun(stateDir, logger)
	case "install-service":
		err = cmdInstallService(stateDir, args)
	case "healthcheck":
		fmt.Printf("huginn-worker %s ok\n", config.Version)
	case "version":
		fmt.Println(config.Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		logger.Error("command failed", "cmd", os.Args[1], "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: huginn-worker <enroll|run|install-service|healthcheck|version> [--state-dir DIR]")
}

// parseStateDir extracts a --state-dir flag from args, returning the remainder.
func parseStateDir(args []string, dir *string) []string {
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--state-dir" && i+1 < len(args) {
			*dir = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return rest
}

func cmdEnroll(stateDir string) error {
	hubURL := os.Getenv("HUB_URL")
	token := os.Getenv("TOKEN")
	if hubURL == "" || token == "" {
		return fmt.Errorf("HUB_URL and TOKEN environment variables are required")
	}
	name := os.Getenv("NAME")
	if name == "" {
		name, _ = os.Hostname()
	}
	allowInsecure := os.Getenv("HUGINN_ALLOW_INSECURE") == "1"

	client, err := hubclient.New(hubclient.Options{BaseURL: hubURL, AllowInsecure: allowInsecure})
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	resp, err := client.Enroll(context.Background(), hubclient.EnrollRequest{
		Token:         token,
		Name:          name,
		Hostname:      hostname,
		Arch:          runtime.GOARCH,
		WorkerVersion: config.Version,
		OSInfo:        map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH},
	})
	if err != nil {
		return err
	}

	state := &config.State{
		HubURL:                 hubURL,
		WorkerID:               resp.WorkerID,
		WorkerSecret:           resp.WorkerSecret,
		AllowInsecureTransport: allowInsecure,
	}
	if err := config.Save(config.StatePath(stateDir), state); err != nil {
		return err
	}
	fmt.Printf("enrolled as %s (state: %s)\n", resp.WorkerID, resp.State)
	fmt.Println("the VM is PENDING; approve it in the dashboard before it can run tasks")
	return nil
}

func cmdRun(stateDir string, logger *slog.Logger) error {
	state, err := config.Load(config.StatePath(stateDir))
	if err != nil {
		return fmt.Errorf("load state (did you enroll?): %w", err)
	}
	client, err := hubclient.New(hubclient.Options{
		BaseURL:       state.HubURL,
		WorkerID:      state.WorkerID,
		WorkerSecret:  state.WorkerSecret,
		AllowInsecure: state.AllowInsecureTransport,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := agent.New(client, state, logger)
	if runErr := a.Run(ctx); runErr != nil && ctx.Err() == nil {
		return runErr
	}
	// A nil return from Run means either a clean shutdown or an applied update;
	// exit 0 so systemd relaunches the (possibly new) binary.
	return nil
}

func cmdInstallService(stateDir string, args []string) error {
	binaryPath := config.DefaultBinaryPath
	if len(args) > 0 {
		binaryPath = args[0]
	}
	unitPath := "/etc/systemd/system/" + systemd.ServiceName + ".service"
	return systemd.Install(unitPath, binaryPath, stateDir)
}
