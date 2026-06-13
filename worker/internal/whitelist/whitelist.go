// Package whitelist maps named actions to fixed argv vectors. Parameters are
// re-validated here (defense in depth) and only ever placed into a separate argv
// slot — never concatenated into a command string.
package whitelist

import (
	"fmt"
	"regexp"
)

// safeName mirrors the hub-side validation: a conservative identifier with no
// shell metacharacters, suitable for things like systemd unit names.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

// Error values for callers to distinguish failure modes.
var (
	ErrUnknownAction = fmt.Errorf("unknown action")
	ErrInvalidParam  = fmt.Errorf("invalid parameter")
)

// builder produces an argv for an action given its (already structural) params.
type builder func(params map[string]string) ([]string, error)

var actions = map[string]builder{
	"status": func(map[string]string) ([]string, error) {
		return []string{"uname", "-a"}, nil
	},
	"metrics": func(map[string]string) ([]string, error) {
		return []string{"cat", "/proc/loadavg"}, nil
	},
	"list_upgradable_packages": func(map[string]string) ([]string, error) {
		return []string{"apt", "list", "--upgradable"}, nil
	},
	"apt_upgrade": func(map[string]string) ([]string, error) {
		return []string{"apt-get", "-y", "upgrade"}, nil
	},
	"restart_service": func(params map[string]string) ([]string, error) {
		service, ok := params["service"]
		if !ok || !safeName.MatchString(service) {
			return nil, fmt.Errorf("%w: service", ErrInvalidParam)
		}
		// service is a single, validated argv element; it can never break out
		// into another command.
		return []string{"systemctl", "restart", service}, nil
	},
}

// BuildArgv returns the argv for a whitelisted action, or an error if the action
// is unknown or its parameters are invalid.
func BuildArgv(action string, params map[string]string) ([]string, error) {
	b, ok := actions[action]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownAction, action)
	}
	return b(params)
}

// Known reports whether an action name is whitelisted.
func Known(action string) bool {
	_, ok := actions[action]
	return ok
}
