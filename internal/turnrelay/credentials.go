package turnrelay

import (
	"crypto/hmac"
	"crypto/sha1" // TURN REST credentials require HMAC-SHA1.
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/pion/turn/v5"

	"github.com/koltyakov/expose/internal/config"
)

// ICEServer can be passed directly to RTCPeerConnection's iceServers option.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

type Credentials struct {
	ICEServers []ICEServer `json:"iceServers"`
	ExpiresAt  int64       `json:"expiresAt"` // Unix seconds.
}

// Credentials issues TURN REST credentials for an authenticated application user.
// The shared secret stays on trusted servers, never in a browser.
func (r *Relay) Credentials(user string) (Credentials, error) {
	if user == "" || len(user) > 128 || strings.ContainsAny(user, "\r\n") {
		return Credentials{}, errors.New("invalid TURN user")
	}
	expires := time.Now().Add(r.cfg.CredentialTTL).Unix()
	username := strconv.FormatInt(expires, 10) + ":" + user
	return Credentials{
		ICEServers: []ICEServer{{URLs: r.URLs(), Username: username, Credential: credential(r.cfg.Secret, username)}},
		ExpiresAt:  expires,
	}, nil
}

func credential(secret, username string) string {
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func authHandler(cfg config.TURNConfig) turn.AuthHandler {
	return func(attrs *turn.RequestAttributes) (string, []byte, bool) {
		if attrs == nil {
			return "", nil, false
		}
		username, realm := attrs.Username, attrs.Realm
		if realm != cfg.Realm || len(username) > 160 {
			return "", nil, false
		}
		timestamp, user, ok := strings.Cut(username, ":")
		expires, err := strconv.ParseInt(timestamp, 10, 64)
		now := time.Now().Unix()
		// Bound accepted lifetimes even when a trusted application mints credentials.
		if !ok || user == "" || err != nil || expires <= now || expires > now+int64((24*time.Hour)/time.Second) {
			return "", nil, false
		}
		return user, turn.GenerateAuthKey(username, realm, credential(cfg.Secret, username)), true
	}
}
