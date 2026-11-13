package cli

import (
	"errors"
	"fmt"
	"os"
)

// ExitError carries one of budctl's documented exit codes out of a command.
// Whatever the operator needs to know has already been printed.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// exitCode wraps a command's result: 0 is success, anything else an ExitError.
func exitCode(code int) error {
	if code == 0 {
		return nil
	}
	return &ExitError{Code: code}
}

// ExitCode maps the error from Execute to the process exit code. Any error
// that is not an ExitError (a bad flag, an unknown command) means budctl could
// not run, and is printed here.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	fmt.Fprintln(os.Stderr, "budctl:", err)
	return 3
}
