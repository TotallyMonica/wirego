package wirego

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
)

type sshHostConfig struct {
	host     string
	user     string
	hostname string
	port     string
}

func (w Wireguard) isRemote() bool {
	return !(strings.Compare(w.Host, "localhost") == 0 ||
		strings.Compare(w.Host, "0.0.0.0") == 0 ||
		strings.Compare(w.Host, "::") == 0 ||
		strings.Compare(w.Host, "[::]") == 0 ||
		strings.Compare(w.Host, "") == 0)
}

func (w Wireguard) getSSHHostConfig(host string) (*sshHostConfig, error) {
	var path = ""
	if strings.Compare(os.ExpandEnv("$HOME"), "") == 0 {
		path = os.ExpandEnv(fmt.Sprintf("$USERPROFILE%c.ssh%cconfig", os.PathSeparator, os.PathSeparator))
	} else {
		path = os.ExpandEnv(fmt.Sprintf("$HOME%c.ssh%cconfig", os.PathSeparator, os.PathSeparator))
	}

	sshConfigFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SSH config: %s", err)
	}
	defer sshConfigFile.Close()

	sshConfig, err := ssh_config.Decode(sshConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load SSH config: %s", err)
	}
	user, err := sshConfig.Get(host, "User")
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH user from config: %s", err)
	}
	hostName, err := sshConfig.Get(host, "HostName")
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH hostname from config: %s", err)
	}
	port, err := sshConfig.Get(host, "Port")
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH port from config: %s", err)
	}
	return &sshHostConfig{host: host, user: user, hostname: hostName, port: port}, nil
}

func (w Wireguard) createSSHClient(host string) (string, *ssh.ClientConfig, error) {
	// Get the full path for the SSH key
	// Windows stores theirs in $USERPROFILE\\.ssh\\id_ed25519 because they're insane
	var path = ""
	if strings.Compare(os.ExpandEnv("$HOME"), "") == 0 {
		path = os.ExpandEnv(fmt.Sprintf("$USERPROFILE%c.ssh%cid_ed25519", os.PathSeparator, os.PathSeparator))
	} else {
		path = os.ExpandEnv(fmt.Sprintf("$HOME%c.ssh%cid_ed25519", os.PathSeparator, os.PathSeparator))
	}
	keyFile, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to open SSH key: %s", err)
	}
	defer keyFile.Close()

	keyBytes, err := io.ReadAll(keyFile)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to read private key: %s", err)
	}

	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to parse private key: %s", err)
	}

	hostConfig, err := w.getSSHHostConfig(host)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to create SSH Client: %s\n", err)
	}

	// Configure SSH client
	sshClientConfig := &ssh.ClientConfig{
		User: hostConfig.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	return net.JoinHostPort(hostConfig.hostname, hostConfig.port), sshClientConfig, nil
}

func (w Wireguard) connectToSSHServer(address string, config ssh.ClientConfig) (*ssh.Client, error) {
	client, err := ssh.Dial("tcp", address, &config)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to %s: %s", address, err)
	}

	return client, nil
}
