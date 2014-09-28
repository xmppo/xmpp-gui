package main

import (
	"bytes"
	"encoding/hex"
//	"encoding/xml"
//	"errors"
//	"flag"
	"fmt"
	"io"
//	"io/ioutil"
	"net/url"
	"os"
//	"os/exec"
//	"os/signal"
//	"path/filepath"
	"reflect"
//	"strconv"
	"strings"
	"sync"
//	"syscall"
	"time"

	"code.google.com/p/go.crypto/otr"
	"code.google.com/p/go.crypto/ssh/terminal"
	"code.google.com/p/go.net/html"
	"code.google.com/p/go.net/proxy"
	"github.com/agl/xmpp"
	"github.com/andlabs/ui"
)

// OTRWhitespaceTagStart may be appended to plaintext messages to signal to the
// remote client that we support OTR. It should be followed by one of the
// version specific tags, below. See "Tagged plaintext messages" in
// http://www.cypherpunks.ca/otr/Protocol-v3-4.0.0.html.
var OTRWhitespaceTagStart = []byte("\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20")

var OTRWhiteSpaceTagV1 = []byte("\x20\x09\x20\x09\x20\x20\x09\x20")
var OTRWhiteSpaceTagV2 = []byte("\x20\x20\x09\x09\x20\x20\x09\x20")
var OTRWhiteSpaceTagV3 = []byte("\x20\x20\x09\x09\x20\x20\x09\x09")

var OTRWhitespaceTag = append(OTRWhitespaceTagStart, OTRWhiteSpaceTagV2...)

func stripHTML(msg []byte) (out []byte) {
	z := html.NewTokenizer(bytes.NewReader(msg))

loop:
	for {
		tt := z.Next()
		switch tt {
		case html.TextToken:
			out = append(out, z.Text()...)
		case html.ErrorToken:
			if err := z.Err(); err != nil && err != io.EOF {
				out = msg
				return
			}
			break loop
		}
	}

	return
}

type Session struct {
	account string
	conn    *xmpp.Conn
	term    *terminal.Terminal
	roster  []xmpp.RosterEntry
	// conversations maps from a JID (without the resource) to an OTR
	// conversation. (Note that unencrypted conversations also pass through
	// OTR.)
	conversations map[string]*otr.Conversation
	// knownStates maps from a JID (without the resource) to the last known
	// presence state of that contact. It's used to deduping presence
	// notifications.
	knownStates map[string]string
	privateKey  *otr.PrivateKey
	config      *Config
	// lastMessageFrom is the JID (without the resource) of the contact
	// that we last received a message from.
	lastMessageFrom string
	// timeouts maps from Cookies (from outstanding requests) to the
	// absolute time when that request should timeout.
	timeouts map[xmpp.Cookie]time.Time
	// pendingRosterEdit, if non-nil, contains information about a pending
	// roster edit operation.
	pendingRosterEdit *rosterEdit
	// pendingRosterChan is the channel over which roster edit information
	// is received.
	pendingRosterChan chan *rosterEdit
	// pendingSubscribes maps JID with pending subscription requests to the
	// ID if the iq for the reply.
	pendingSubscribes map[string]string
	// lastActionTime is the time at which the user last entered a command,
	// or was last notified.
	lastActionTime time.Time
}

// rosterEdit contains information about a pending roster edit. Roster edits
// occur by writing the roster to a file and inviting the user to edit the
// file.
type rosterEdit struct {
	// fileName is the name of the file containing the roster information.
	fileName string
	// roster contains the state of the roster at the time of writing the
	// file. It's what we diff against when reading the file.
	roster []xmpp.RosterEntry
	// isComplete is true if this is the result of reading an edited
	// roster, rather than a report that the file has been written.
	isComplete bool
	// contents contains the edited roster, if isComplete is true.
	contents []byte
}

func (s *Session) readMessages(stanzaChan chan<- xmpp.Stanza) {
	defer close(stanzaChan)

	for {
		stanza, err := s.conn.Next()
		if err != nil {
			fmt.Printf("%s\n", err.Error())
			return
		}
		stanzaChan <- stanza
	}
}

func main() {
	term := terminal.NewTerminal(os.Stdin, "> ")

	// Import the configuration
	fmt.Printf("Importing the config...\n")
	config := importConfig();

	// Set up an array for all of our sessions
	var sessions = make([]Session, len(config.Accounts))

	// If no accounts are configured, open the accounts interface
	if len(config.Accounts) < 1 {
		fmt.Printf("Loading the accounts interface...\n")
		go ui.Do(listAccounts)
		err := ui.Go()
		if err != nil {
			panic(err)
		}
	// Otherwise, connect
	} else {
		// TODO: add connections for other users 
		fmt.Printf("Loading account 0...\n")
		account := config.Accounts[0]

		user := account.Name
		domain := account.Domain

		// TODO: encrypt/decrypt this, derp
		password := account.Password

		var addr string
		addrTrusted := false

		if len(account.Server) > 0 && account.Port > 0 {
			addr = fmt.Sprintf("%s:%d", account.Server, account.Port)
			addrTrusted = true
			fmt.Printf("We trust this server at: %s\n", addr)
		} else {
			if len(config.Proxies) > 0 {
				fmt.Printf("Cannot connect via a proxy without Server and Port being set in the config file as an SRV lookup would leak information.\n")
				return
			}
			host, port, err := xmpp.Resolve(domain)
			if err != nil {
				fmt.Printf("Failed to resolve XMPP server: %s\n", err.Error())
				return
			}
			addr = fmt.Sprintf("%s:%d", host, port)
		}

		fmt.Printf("Address of XMPP server: %s", addr)
		var dialer proxy.Dialer
		for i := len(config.Proxies) - 1; i >= 0; i-- {
			u, err := url.Parse(config.Proxies[i])
			if err != nil {
				fmt.Printf("Failed to parse "+config.Proxies[i]+" as a URL: %s\n", err.Error())
				return
			}
			if dialer == nil {
				dialer = proxy.Direct
			}
			if dialer, err = proxy.FromURL(u, dialer); err != nil {
				fmt.Printf("Failed to parse "+config.Proxies[i]+" as a proxy: %s\n", err.Error())
				return
			}
		}

		var certSHA256 []byte
		if len(account.ServerCertificateSHA256) > 0 {
			certSHA256, err := hex.DecodeString(account.ServerCertificateSHA256)
			if err != nil {
				fmt.Printf("Failed to parse ServerCertificateSHA256 (should be hex string): %s\n", err.Error())
				return
			}
			if len(certSHA256) != 32 {
				fmt.Printf("ServerCertificateSHA256 is not 32 bytes long\n")
				return
			}
		}

		xmppConfig := &xmpp.Config{
			Log:                     &lineLogger{term, nil},
//			Create:                  *createAccount,
			TrustedAddress:          addrTrusted,
			Archive:                 false,
			ServerCertificateSHA256: certSHA256,
		}

		if len(config.RawLogFile) > 0 {
			rawLog, err := os.OpenFile(config.RawLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				fmt.Printf("Failed to open raw log file: %s", err.Error())
				return
			}

			lock := new(sync.Mutex)
			in := rawLogger{
				out:    rawLog,
				prefix: []byte("<- "),
				lock:   lock,
			}
			out := rawLogger{
				out:    rawLog,
				prefix: []byte("-> "),
				lock:   lock,
			}
			in.other, out.other = &out, &in

			xmppConfig.InLog = &in
			xmppConfig.OutLog = &out
			xmppConfig.Log = &out

			defer in.flush()
			defer out.flush()
		}

		if dialer != nil {
			fmt.Printf("Making connection to %s via proxy\n", addr)
			var err error
			if xmppConfig.Conn, err = dialer.Dial("tcp", addr); err != nil {
				fmt.Printf("Failed to connect via proxy: %s\n", err.Error())
				return
			}
		}

		fmt.Printf("Connecting %s@%s to %s", user, domain, addr)
		conn, err := xmpp.Dial(addr, user, domain, password, xmppConfig)
		if err != nil {
			fmt.Printf("Failed to connect to XMPP server: %s", err.Error())
			return
		}

		fmt.Printf("Connected, establishing session...\n")
		s := Session{
			account:           strings.Join([]string{config.Accounts[0].Name, config.Accounts[0].Domain}, "@"),
			conn:              conn,
			term:              term,
			conversations:     make(map[string]*otr.Conversation),
			knownStates:       make(map[string]string),
			privateKey:        new(otr.PrivateKey),
			config:            config,
			pendingRosterChan: make(chan *rosterEdit),
			pendingSubscribes: make(map[string]string),
			lastActionTime:    time.Now(),
		}

		//var rosterReply chan xmpp.Stanza
		fmt.Printf("Requesting roster...\n")
		rosterReply, _, err := s.conn.RequestRoster()
		if err != nil {
			fmt.Printf("Failed to request roster: %s\n", err.Error())
			return
		}

		fmt.Printf("TypeOf rosterReply: %s\n", reflect.TypeOf(rosterReply))

		conn.SignalPresence("")
	}
}

type rawLogger struct {
	out    io.Writer
	prefix []byte
	lock   *sync.Mutex
	other  *rawLogger
	buf    []byte
}

func (r *rawLogger) Write(data []byte) (int, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if err := r.other.flush(); err != nil {
		return 0, nil
	}

	origLen := len(data)
	for len(data) > 0 {
		if newLine := bytes.IndexByte(data, '\n'); newLine >= 0 {
			r.buf = append(r.buf, data[:newLine]...)
			data = data[newLine+1:]
		} else {
			r.buf = append(r.buf, data...)
			data = nil
		}
	}

	return origLen, nil
}

var newLine = []byte{'\n'}

func (r *rawLogger) flush() error {
	if len(r.buf) == 0 {
		return nil
	}

	if _, err := r.out.Write(r.prefix); err != nil {
		return err
	}
	if _, err := r.out.Write(r.buf); err != nil {
		return err
	}
	if _, err := r.out.Write(newLine); err != nil {
		return err
	}
	r.buf = r.buf[:0]
	return nil
}

type lineLogger struct {
	term *terminal.Terminal
	buf  []byte
}

func (l *lineLogger) logLines(in []byte) []byte {
	for len(in) > 0 {
		if newLine := bytes.IndexByte(in, '\n'); newLine >= 0 {
			info(l.term, string(in[:newLine]))
			in = in[newLine+1:]
		} else {
			break
		}
	}
	return in
}

func (l *lineLogger) Write(data []byte) (int, error) {
	origLen := len(data)

	if len(l.buf) == 0 {
		data = l.logLines(data)
	}

	if len(data) > 0 {
		l.buf = append(l.buf, data...)
	}

	l.buf = l.logLines(l.buf)
	return origLen, nil
}

// appendTerminalEscaped acts like append(), but breaks terminal escape
// sequences that may be in msg.
func appendTerminalEscaped(out, msg []byte) []byte {
	for _, c := range msg {
		if c == 127 || (c < 32 && c != '\t') {
			out = append(out, '?')
		} else {
			out = append(out, c)
		}
	}
	return out
}

func terminalMessage(term *terminal.Terminal, color []byte, msg string, critical bool) {
	line := make([]byte, len(msg)+16)[:0]

	line = append(line, ' ')
	line = append(line, color...)
	line = append(line, '*')
	line = append(line, term.Escape.Reset...)
	line = append(line, []byte(fmt.Sprintf(" (%s) ", time.Now().Format(time.Kitchen)))...)
	if critical {
		line = append(line, term.Escape.Red...)
	}
	line = appendTerminalEscaped(line, []byte(msg))
	if critical {
		line = append(line, term.Escape.Reset...)
	}
	line = append(line, '\n')
	term.Write(line)
}

func info(term *terminal.Terminal, msg string) {
	terminalMessage(term, term.Escape.Blue, msg, false)
}

func warn(term *terminal.Terminal, msg string) {
	terminalMessage(term, term.Escape.Magenta, msg, false)
}

func alert(term *terminal.Terminal, msg string) {
	terminalMessage(term, term.Escape.Red, msg, false)
}

func critical(term *terminal.Terminal, msg string) {
	terminalMessage(term, term.Escape.Red, msg, true)
}
