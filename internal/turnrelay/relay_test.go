package turnrelay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/turn/v5"

	"github.com/koltyakov/expose/internal/config"
)

func testConfig(t *testing.T) config.TURNConfig {
	t.Helper()
	// Choose an available relay port without relying on fixed test ports.
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	_ = socket.Close()
	return config.TURNConfig{
		Enabled: true, ListenUDP: "127.0.0.1:0", ListenTCP: "127.0.0.1:0",
		PublicIP: "127.0.0.1", Host: "127.0.0.1", Secret: strings.Repeat("s", 32), Realm: "example.com",
		RelayAddress: "127.0.0.1", MinPort: port, MaxPort: port,
		MaxAllocations: 8, MaxConnections: 8, CredentialTTL: time.Hour,
	}
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func udpAllocation(port int) turn.AllocateListenerConfig {
	return turn.AllocateListenerConfig{Network: "udp4", RequestedPort: port}
}

func TestCredentialsAndAuthentication(t *testing.T) {
	cfg := testConfig(t)
	cfg.ListenUDP, cfg.ListenTCP, cfg.ListenTLS = ":3478", ":3478", ":5349"
	r := &Relay{cfg: cfg}
	creds, err := r.Credentials("app-user")
	if err != nil {
		t.Fatal(err)
	}
	ice := creds.ICEServers[0]
	want := []string{"turn:127.0.0.1:3478?transport=udp", "turn:127.0.0.1:3478?transport=tcp", "turns:127.0.0.1:5349?transport=tcp"}
	if strings.Join(ice.URLs, ",") != strings.Join(want, ",") || !strings.HasSuffix(ice.Username, ":app-user") || creds.ExpiresAt < time.Now().Add(59*time.Minute).Unix() {
		t.Fatalf("unexpected credentials: %+v", creds)
	}
	auth := authHandler(cfg)
	userID, key, ok := auth(&turn.RequestAttributes{Username: ice.Username, Realm: cfg.Realm})
	if !ok || userID != "app-user" || !bytes.Equal(key, turn.GenerateAuthKey(ice.Username, cfg.Realm, ice.Credential)) {
		t.Fatal("issued credentials do not authenticate")
	}
	// Check interoperability with Pion's standard TURN REST issuer.
	username, password, err := turn.GenerateLongTermTURNRESTCredentials(cfg.Secret, "external-app", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	userID, key, ok = auth(&turn.RequestAttributes{Username: username, Realm: cfg.Realm})
	if !ok || userID != "external-app" || !bytes.Equal(key, turn.GenerateAuthKey(username, cfg.Realm, password)) {
		t.Fatal("standard TURN REST credentials do not authenticate")
	}
	for _, username := range []string{"invalid", "0:user", strconv.FormatInt(time.Now().Unix(), 10) + ":user", strconv.FormatInt(time.Now().Add(25*time.Hour).Unix(), 10) + ":user", "9999999999999999999999999:user", "123:"} {
		if _, _, ok := auth(&turn.RequestAttributes{Username: username, Realm: cfg.Realm}); ok {
			t.Fatalf("accepted invalid username %q", username)
		}
	}
	if _, _, ok := auth(&turn.RequestAttributes{Username: ice.Username, Realm: "other-realm"}); ok {
		t.Fatal("accepted incorrect realm")
	}
	if _, _, ok := auth(nil); ok {
		t.Fatal("accepted missing request attributes")
	}
	if _, err := r.Credentials(""); err == nil {
		t.Fatal("accepted empty user")
	}
}

func TestPeerPermissions(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "0.1.2.3", "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "::1", "2001:4860:4860::8888", "::ffff:192.168.1.1", "invalid"} {
		if publicPeerPermission(nil, net.ParseIP(ip)) {
			t.Errorf("allowed non-public peer %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "::ffff:8.8.8.8"} {
		if !publicPeerPermission(nil, net.ParseIP(ip)) {
			t.Errorf("blocked public peer %s", ip)
		}
	}
}

func TestAllocatorLimitsAndCleanup(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxAllocations = 1
	g := newRelayGenerator(cfg)
	t.Cleanup(g.close)
	if _, _, err := g.AllocatePacketConn(udpAllocation(cfg.MinPort - 1)); err == nil {
		t.Fatal("allowed allocation outside configured range")
	}
	if _, _, err := g.AllocatePacketConn(udpAllocation(cfg.MaxPort + 1)); err == nil {
		t.Fatal("allowed allocation above configured range")
	}
	conn, addr, err := g.AllocatePacketConn(udpAllocation(cfg.MinPort))
	if err != nil {
		t.Fatal(err)
	}
	if addr.(*net.UDPAddr).Port != cfg.MinPort {
		t.Fatal("incorrect advertised port")
	}
	if _, _, err := g.AllocatePacketConn(udpAllocation(0)); err == nil {
		t.Fatal("allocation limit not enforced")
	}
	_ = conn.Close()
	_ = conn.Close()
	conn, _, err = g.AllocatePacketConn(udpAllocation(0))
	if err != nil {
		t.Fatalf("allocation slot not released: %v", err)
	}
	g.close()
	if _, _, err := g.AllocatePacketConn(udpAllocation(0)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("allocated after shutdown")
	}
	if _, _, err := conn.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("relay socket survived shutdown")
	}
}

func TestAllocatorConcurrentLimit(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxAllocations = 1
	g := newRelayGenerator(cfg)
	defer g.close()
	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := 0
	for range 20 {
		wg.Go(func() {
			if _, _, err := g.AllocatePacketConn(udpAllocation(0)); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if succeeded != 1 {
		t.Fatalf("concurrent allocations exceeded limit: %d", succeeded)
	}
}

func TestAllocatorRejectsUnsupportedTransports(t *testing.T) {
	g := newRelayGenerator(testConfig(t))
	defer g.close()
	for _, network := range []string{"udp6", "tcp4", "tcp6"} {
		if _, _, err := g.AllocatePacketConn(turn.AllocateListenerConfig{Network: network}); err == nil {
			t.Fatalf("accepted unsupported packet allocation network %q", network)
		}
	}
	if _, _, err := g.AllocateListener(turn.AllocateListenerConfig{Network: "tcp4"}); err == nil {
		t.Fatal("accepted a TCP relay allocation")
	}
	if _, err := g.AllocateConn(turn.AllocateConnConfig{Network: "tcp4"}); err == nil {
		t.Fatal("accepted an outbound TCP relay connection")
	}
}

func TestTURNRelaysPacketsOverUDPAndTCPAndTLS(t *testing.T) {
	for _, transport := range []string{"udp", "tcp", "tls"} {
		t.Run(transport, func(t *testing.T) {
			cfg := testConfig(t)
			var tlsConfig *tls.Config
			if transport == "tls" {
				cfg.ListenTLS = "127.0.0.1:0"
				tlsConfig = testTLSConfig(t)
			}
			// Only this test allows loopback peers. Production Start always uses
			// publicPeerPermission, which is tested separately.
			r, err := start(cfg, tlsConfig, testLogger(), turn.DefaultPermissionHandler)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			creds, _ := r.Credentials("test-user")
			ice := creds.ICEServers[0]
			addr := r.cfg.ListenUDP
			var socket net.PacketConn
			if transport == "udp" {
				socket, err = net.ListenPacket("udp4", "127.0.0.1:0")
			} else {
				addr = r.cfg.ListenTCP
				var conn net.Conn
				if transport == "tls" {
					addr = r.cfg.ListenTLS
					// Trust the fixture certificate, rather than disabling verification.
					roots := x509.NewCertPool()
					cert, parseErr := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					roots.AddCert(cert)
					conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp4", addr, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
				} else {
					conn, err = net.DialTimeout("tcp4", addr, 3*time.Second)
				}
				if err == nil {
					socket = turn.NewSTUNConn(conn)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = socket.Close() })
			client, err := turn.NewClient(&turn.ClientConfig{TURNServerAddr: addr, Conn: socket, Username: ice.Username, Password: ice.Credential, RTO: 10 * time.Millisecond, LoggerFactory: logFactory{testLogger()}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			if err := client.Listen(); err != nil {
				t.Fatal(err)
			}
			relay, err := client.Allocate()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = relay.Close() })
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
			_ = relay.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("opaque DTLS packet")
			if _, err := relay.WriteTo(payload, peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 128)
			n, from, err := peer.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("relay to peer: %q, %v", buf[:n], err)
			}
			if _, err := peer.WriteTo(payload, from); err != nil {
				t.Fatal(err)
			}
			n, _, err = relay.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("peer to relay: %q, %v", buf[:n], err)
			}
		})
	}
}

func TestStartupFailureClosesListeners(t *testing.T) {
	cfg := testConfig(t)
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenUDP = udp.LocalAddr().String()
	_ = udp.Close()
	cfg.ListenTCP = occupied.Addr().String()
	if _, err := Start(cfg, nil, testLogger()); err == nil {
		t.Fatal("startup should fail on occupied TCP port")
	}
	udp, err = net.ListenPacket("udp4", cfg.ListenUDP)
	if err != nil {
		t.Fatalf("UDP listener leaked after startup failure: %v", err)
	}
	_ = udp.Close()
	cfg.ListenTLS = "127.0.0.1:5349"
	if _, err := Start(cfg, nil, testLogger()); err == nil {
		t.Fatal("TLS startup accepted missing certificate provider")
	}
}

func TestRejectsInvalidCredentialsAndPrivatePermissions(t *testing.T) {
	cfg := testConfig(t)
	r, err := Start(cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	creds, err := r.Credentials("test-user")
	if err != nil {
		t.Fatal(err)
	}
	ice := creds.ICEServers[0]
	newClient := func(username, password string) *turn.Client {
		t.Helper()
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		client, err := turn.NewClient(&turn.ClientConfig{
			TURNServerAddr: r.cfg.ListenUDP, Conn: socket, Username: username, Password: password,
			RTO: 10 * time.Millisecond, LoggerFactory: logFactory{testLogger()},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		if err := client.Listen(); err != nil {
			t.Fatal(err)
		}
		return client
	}
	for _, invalid := range []struct{ user, pass string }{
		{ice.Username, "incorrect-password"},
		{"0:expired", credential(cfg.Secret, "0:expired")},
		{"invalid", credential(cfg.Secret, "invalid")},
	} {
		if _, err := newClient(invalid.user, invalid.pass).Allocate(); err == nil {
			t.Fatalf("invalid credentials obtained an allocation: %q", invalid.user)
		}
	}
	client := newClient(ice.Username, ice.Credential)
	relay, err := client.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254"} {
		if err := client.CreatePermission(&net.UDPAddr{IP: net.ParseIP(ip), Port: 8080}); err == nil {
			t.Errorf("TURN allowed a permission to %s", ip)
		}
	}
	if err := client.CreatePermission(&net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 8080}); err != nil {
		t.Errorf("TURN rejected a public permission: %v", err)
	}
}

func TestUnauthenticatedConnectionDeadline(t *testing.T) {
	p := newConnectionPool(1)
	server, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	c, ok := p.add(server)
	if !ok {
		t.Fatal("could not track connection")
	}
	defer p.close()
	// An expired initial authentication deadline must remain expired even
	// when the client supplies partial STUN messages or repeated reads.
	c.authDeadline = time.Now().Add(-time.Second)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("unauthenticated connection ignored its deadline")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected authentication timeout, got %v", err)
	}
	p.authenticated(c.RemoteAddr(), c.LocalAddr())
	if !c.ready.Load() {
		t.Fatal("successful authentication was not tracked")
	}
	done := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte{1})
		done <- err
	}()
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatalf("authenticated connection kept the initial deadline: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	other, otherPeer := net.Pipe()
	defer func() { _ = otherPeer.Close() }()
	if _, ok := p.add(other); !ok {
		_ = other.Close()
		t.Fatal("connection slot not released")
	}
}

func TestConnectionLimitsAndShutdown(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxConnections = 1
	r, err := Start(cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	first, err := net.DialTimeout("tcp4", r.cfg.ListenTCP, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		r.peers.mu.Lock()
		n := len(r.peers.conns)
		r.peers.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first connection was not accepted")
		}
		time.Sleep(time.Millisecond)
	}
	second, err := net.DialTimeout("tcp4", r.cfg.ListenTCP, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess connection was not closed")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess connection stayed open")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal("Close must be idempotent")
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("unauthenticated connection survived shutdown")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("shutdown left connection open")
	}
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TURN test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}
