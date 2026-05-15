package wirego

import (
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	_ "golang.org/x/crypto/ssh"
)

type Peer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	PeerIP              string
	LatestHandshake     time.Time
	BytesTx             int
	BytesRx             int
	PersistentKeepalive string
}

type Conn struct {
	PublicKey   string
	PrivateKey  string
	ListenPort  int
	ForwardMark string
	Peers       []Peer
}

type Wireguard struct {
	Host             string
	Path             string
	RemoteConnection *ssh.Client
}

func New(host string) (Wireguard, error) {
	var wireguardInstance = Wireguard{Host: host, Path: ""}
	exists, path := wireguardInstance.checkForPrerequisites()
	if exists {
		wireguardInstance.Path = path
		return wireguardInstance, nil
	} else {
		return Wireguard{}, DependencyError{"wg"}
	}
}

func (w Wireguard) checkForPrerequisites() (bool, string) {
	var path string
	var err error

	var dependencies = []string{"wg"}

	for dependency := range dependencies {
		if !w.isRemote() {
			path, err = exec.LookPath(dependency)
			if err != nil {
				return false, ""
			}
		} else {
			address, config, err := w.createSSHClient(w.Host)
			if err != nil {
				return false, ""
			}
			client, err := w.connectToSSHServer(address, *config)
			if err != nil {
				return false, ""
			}
			defer client.Close()

			session, err := client.NewSession()
			if err != nil {
				return false, ""
			}

			stdout, err := session.StdoutPipe()
			if err != nil {
				return false, ""
			}
			if err := session.Start(fmt.Sprintf("which %s", dependency)); err != nil {
				return false, ""
			}
			output, err := io.ReadAll(stdout)
			if err != nil {
				return false, ""
			}
			if err := session.Wait(); err != nil {
				return false, ""
			}
			path = string(output)
		}
		return strings.Compare(path, "") != 0 && strings.Compare(path, fmt.Sprintf("%s not found", dependency)) != 0, path
	}

	return strings.Compare(path, "") != 0 && strings.Compare(path, fmt.Sprintf("%s not found", dependencies[0])) != 0, path
}

func (w Wireguard) executeCommand() (strings.Builder, strings.Builder, error) {
	var stdout strings.Builder
	var stderr strings.Builder

	if w.isRemote() {
		address, config, err := w.createSSHClient(w.Host)
		if err != nil {
			return strings.Builder{}, strings.Builder{}, fmt.Errorf("could not create client: %v", err)
		}
		client, err := w.connectToSSHServer(address, *config)
		if err != nil {
			return strings.Builder{}, strings.Builder{}, fmt.Errorf("could not connect to server %s: %v", address, err)
		}
		defer client.Close()

		session, err := client.NewSession()
		if err != nil {
			return strings.Builder{}, strings.Builder{}, fmt.Errorf("could not create session: %v", err)
		}

		session.Stdout = &stdout
		session.Stderr = &stderr

		if err := session.Start("wg show all dump"); err != nil {
			return strings.Builder{}, strings.Builder{}, fmt.Errorf("could not execute `wg show all dump`: %v", err)
		}
		if err := session.Wait(); err != nil {
			return strings.Builder{}, strings.Builder{}, fmt.Errorf("error while waiting for session to finish: %v", err)
		}
	} else {
		cmd := exec.Command(w.Path, "show", "all", "dump")
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			return strings.Builder{}, strings.Builder{}, fmt.Errorf("could not execute %s: %v", cmd.String(), err)
		}
	}

	return stdout, stderr, nil
}

func (w Wireguard) GetConnections() (map[string]*Conn, error) {
	conn := make(map[string]*Conn)

	stdout, stderr, err := w.executeCommand()
	if err != nil {
		return nil, err
	}

	if strings.Compare(stderr.String(), "") != 0 {
		return nil, fmt.Errorf("unexpected stderr: %s", stderr.String())
	}

	for _, row := range strings.Split(stdout.String(), "\n") {
		cols := strings.Split(row, "\t")
		if len(cols) == 5 {
			listenPort, err := strconv.Atoi(cols[3])
			if err != nil && strings.Compare(cols[3], "(none)") != 0 {
				return nil, fmt.Errorf("could not parse listening port: %s\n", err)
			}
			newConn := Conn{
				PublicKey:   cols[1],
				PrivateKey:  cols[2],
				ListenPort:  listenPort,
				Peers:       make([]Peer, 0),
				ForwardMark: cols[4],
			}

			conn[cols[0]] = &newConn
		} else if len(cols) == 9 {
			latestHandshake, err := strconv.Atoi(cols[5])
			if err != nil {
				return nil, fmt.Errorf("could not parse latest handshake %s: %v\n", cols[5], err)
			}
			bytesTx, err := strconv.Atoi(cols[6])
			if err != nil {
				return nil, fmt.Errorf("could not parse transmitted bytes %s: %v\n", cols[6], err)
			}
			bytesRx, err := strconv.Atoi(cols[7])
			if err != nil {
				return nil, fmt.Errorf("could not parse received bytes %s: %v\n", cols[7], err)
			}

			newPeer := Peer{
				PublicKey:           cols[1],
				PresharedKey:        cols[2],
				PeerIP:              cols[3],
				AllowedIPs:          strings.Split(cols[4], ","),
				LatestHandshake:     time.Unix(int64(latestHandshake), 0),
				BytesTx:             bytesTx,
				BytesRx:             bytesRx,
				PersistentKeepalive: cols[8],
			}

			conn[cols[0]].Peers = append(conn[cols[0]].Peers, newPeer)
		}
	}

	return conn, nil
}
