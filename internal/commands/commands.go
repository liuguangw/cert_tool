package commands

import (
	"github.com/spf13/cobra"
)

// Execute 执行命令行程序
func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "cert_tool",
		Short: "Certificate Generation Tool",
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(makeCaCommand())
	rootCmd.AddCommand(makeCertCommand())
	return rootCmd.Execute()
}
