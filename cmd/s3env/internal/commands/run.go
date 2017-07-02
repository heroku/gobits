package commands

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run <command> [ARG]...",
	Short: "run a process with config vars on process env",
	Long: `run takes any command and passes through all the config vars.
It uses exec(3) to pass complete control to the process, and
therefore all signals are properly delegated.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			displayUsage(cmd)
		}

		target := args[0] // The wrapped command we'll execute.
		exe, err := exec.LookPath(target)
		if err != nil {
			displayErr(err)
		}

		env := merge(s3vars, os.Environ())

		// pass control to the given cmd. This also means all signal
		// handling is delegated at this point to the cmd.
		if err = syscall.Exec(exe, args, env); err != nil {
			displayErr(err)
		}
	},
}

// merge takes a map of envs and a slice and combines them into one slice.
// e.g. given "A" => 1, and []{"B=2"}, you get {"A=1", "B=2"}
func merge(env map[string]string, environ []string) []string {
	result := make([]string, 0, len(env)+len(environ))

	for _, kv := range environ {
		result = append(result, kv)
	}

	for k, v := range env {
		result = append(result, k+"="+v)
	}

	return result
}
