package utils

import (
	"bufio"
	"os"
	"strings"
)

func IsStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false

	}
	return (stat.Mode() & os.ModeCharDevice) == 0

}
func ReadInputFromStdin() ([]string, error) {
	hosts := []string{}

	Scanner := bufio.NewScanner(os.Stdin)
	for Scanner.Scan() {
		if Scanner.Text() == "" {
			continue
		}
		hosts = append(hosts, strings.TrimSpace(Scanner.Text()))

	}

	return hosts, nil
}
func ReadInputFromFile(path string) ([]string, error) {
	hosts := []string{}
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(fileData)))
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		hosts = append(hosts, scanner.Text())
	}

	return hosts, nil
}
