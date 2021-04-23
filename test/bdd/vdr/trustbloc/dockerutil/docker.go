/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dockerutil

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DockerHelper helper for docker specific functions.
type DockerHelper interface {
	GetIPAddress(containerID string) (string, error)
	RemoveContainersWithNamePrefix(namePrefix string) error
}

// NewDockerCmdlineHelper returns a new command line DockerHelper instance.
func NewDockerCmdlineHelper() DockerHelper {
	return &dockerCmdlineHelper{}
}

type dockerCmdlineHelper struct{}

func splitDockerCommandResults(cmdOutput string) (linesToReturn []string) {
	lines := strings.Split(cmdOutput, "\n")
	for _, line := range lines {
		if len(line) > 0 {
			linesToReturn = append(linesToReturn, line)
		}
	}

	return linesToReturn
}

func (d *dockerCmdlineHelper) issueDockerCommand(cmdArgs []string) (string, error) {
	var cmdOut []byte

	var err error

	cmd := exec.Command("docker", cmdArgs...) //nolint: gosec
	cmdOut, err = cmd.CombinedOutput()

	return string(cmdOut), err
}

func (d *dockerCmdlineHelper) getContainerIDsWithNamePrefix(namePrefix string) ([]string, error) {
	cmdOutput, err := d.issueDockerCommand([]string{"ps", "--filter", fmt.Sprintf("name=%s", namePrefix), "-qa"})
	if err != nil {
		return nil, fmt.Errorf("error getting containers with name prefix '%s':  %w",
			namePrefix, err)
	}

	containerIDs := splitDockerCommandResults(cmdOutput)

	return containerIDs, err
}

func (d *dockerCmdlineHelper) GetIPAddress(containerID string) (ipAddress string, err error) {
	var (
		cmdOutput string
		lines     []string
	)

	errRetFunc := func() error {
		return fmt.Errorf("error getting IPAddress for container '%s':  %w", containerID, err)
	}

	if cmdOutput, err = d.issueDockerCommand([]string{
		"inspect",
		"--format",
		"{{ .NetworkSettings.IPAddress }}",
		containerID,
	}); err != nil {
		return "", errRetFunc()
	}

	if lines = splitDockerCommandResults(cmdOutput); len(lines) != 1 {
		err = fmt.Errorf("unexpected length on inspect output")

		return "", errRetFunc()
	}

	ipAddress = lines[0]

	return ipAddress, nil
}

func (d *dockerCmdlineHelper) RemoveContainersWithNamePrefix(namePrefix string) error {
	containers, err := d.getContainerIDsWithNamePrefix(namePrefix)
	if err != nil {
		return fmt.Errorf("error removing containers with name prefix (%s):  %w", namePrefix, err)
	}

	for _, id := range containers {
		fmt.Printf("container: %s", id)

		_, err = d.issueDockerCommand([]string{"rm", "-f", id})
		if err != nil {
			return fmt.Errorf("failed to issue docker command:  %w", err)
		}
	}

	return nil
}

// GenerateSplitLogs generates a log file named logName, formatted similarly to docker-compose logs,
// but without all the output from all the containers being mixed in together.
// Each container has all its output in one section of the log, for easy reading.
func GenerateSplitLogs(logName string) error { // nolint:funlen
	helper := dockerCmdlineHelper{}

	containerNames, err := helper.issueDockerCommand([]string{
		"ps",
		"--filter", "label=com.docker.compose.project",
		"--format", `{{.Names}}`,
	})
	if err != nil {
		return fmt.Errorf("failed to get list of containers: %w", err)
	}

	// each line is a comma-separated list of names for a container
	nameLists := splitDockerCommandResults(containerNames)

	noColor, colorList := ansiColors()
	colorIdx := 0

	f, err := os.OpenFile(logName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600) // nolint: gosec
	if err != nil {
		return err
	}

	defer func() {
		if errClose := f.Close(); errClose != nil {
			fmt.Println(errClose.Error())
		}
	}()

	out := bufio.NewWriter(f)

	for _, namesString := range nameLists {
		names := strings.Split(namesString, ",")
		if len(names) == 0 || names[0] == "" {
			continue
		}

		name := names[0]

		formattedName := fmt.Sprintf("%s| %s | %s", colorList[colorIdx], name, noColor)

		var logLines []string

		rawLog, _ := helper.issueDockerCommand([]string{"logs", name}) // nolint:errcheck
		logLines = splitDockerCommandResults(rawLog)

		for _, line := range logLines {
			_, _ = out.WriteString(formattedName) // nolint:errcheck
			_, _ = out.WriteString(line)          // nolint:errcheck
			_ = out.WriteByte('\n')               // nolint:errcheck
		}

		colorIdx++
		if colorIdx >= len(colorList) {
			colorIdx = 0
		}
	}

	err = out.Flush()
	if err != nil {
		return fmt.Errorf("failed to write log file: %w", err)
	}

	return nil
}

// returns the ansi terminal format reset code and a list of ansi color codes.
func ansiColors() (string, []string) { //nolint:gocritic
	return "\033[0m", []string{
		"\033[31m", // red
		"\033[32m", // green
		"\033[34m", // blue
		"\033[90m", // gray
		"\033[91m", // bright red
		"\033[94m", // bright blue
		"\033[33m", // yellow
		"\033[36m", // cyan
		"\033[35m", // magenta
		"\033[92m", // bright green
		"\033[95m", // bright magenta
	}
}
