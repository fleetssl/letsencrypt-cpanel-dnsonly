package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/eggsampler/acme/v2"
)

const (
	defaultStatePath = "/var/lib/fleetssl-dnsonly.json"
	defaultConfPath  = "/etc/fleetssl-dnsonly.conf"
)

var (
	isDryRun    bool
	isReinstall bool

	statePath string
	confPath  string
	state     = &stateFile{}
	config    = &configFile{}

	version = "dev"

	installTargets = [][]string{{"cpanel", "cpsrvd"}, {"dovecot", "imap"}, {"exim", "exim"}}
)

type stateFile struct {
	// Map of Directory URL => PEM-Encoded Key
	ACMEAccountKeys map[string][]byte

	// PEM-Encoded certificate chain
	CertificateChain []byte
	// PEM-encoded certificate private key
	CertificatePrivateKey []byte

	needsPersist bool
}

type configFile struct {
	ACMEDirectory       string
	ACMEDryRunDirectory string
	ACMEKeySpec         string
	ACMEEmailAddress    string

	CSRKeySpec   string
	CSRHostnames []string

	ListenPort int

	RenewalCutoff time.Duration
}

func main() {
	flag.StringVar(&statePath, "state", envOrDefault("STATE_PATH", defaultStatePath), "Storage path for program state")
	flag.StringVar(&confPath, "conf", envOrDefault("CONF_PATH", defaultConfPath), "Storage path for program configuration")
	flag.BoolVar(&isDryRun, "dry-run", false, "Whether to limit renewal to a dry-run only")
	flag.BoolVar(&isReinstall, "reinstall", false, "Whether to only perform re-installation of the existing certificate")
	flag.Parse()

	if isDryRun && isReinstall {
		log.Fatal("--dry-run and --reinstall are mutually exclusive.")
	}

	if err := loadConfig(); err != nil {
		log.Fatalf("Configuration was not valid: %v", err)
	}
	if err := loadState(); err != nil {
		log.Fatalf("Could not load state from %s: %v", statePath, err)
	}

	needToIssue, reason := checkNeedsToIssue()
	if !needToIssue {
		log.Printf("No need to issue a certificate, exiting: %s", reason)
		return
	}

	if !isReinstall {
		log.Printf("Will issue certificate because: %s", reason)
		if err := issue(); err != nil {
			log.Fatalf("Failed to issue certificate: %v", err)
		}
	}

	if !isDryRun && (isReinstall || needToIssue) {
		log.Println("Will perform certificate installation")
		if err := install(); err != nil {
			log.Printf("Failed to install certificate: %v", err)
		}
	}
}

func install() error {
	// Quick trick to find the boundary between the leaf and the issuer chain
	_, rest := pem.Decode(state.CertificateChain)
	leaf := string(state.CertificateChain[:bytes.Index(state.CertificateChain, rest)])
	bundle := string(rest)

	keyPEM := string(derToPEM(state.CertificatePrivateKey, "PRIVATE KEY"))

	for _, target := range installTargets {
		log.Printf("Deploying certificate to: %s", target[0])
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/sbin/whmapi1",
			"install_service_ssl_certificate", "service="+target[0],
			"crt="+url.QueryEscape(leaf), "key="+url.QueryEscape(keyPEM),
			"cabundle="+url.QueryEscape(bundle))
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Failed to install certificate to %s: %v: %s", target[0], err, string(out))
			continue
		}

		log.Printf("Restarting service %s", target[1])
		ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel2()
		cmd = exec.CommandContext(ctx2, "/usr/sbin/whmapi1", "service="+target[1])
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Printf("Failed to restart service for %s: %v: %s", target[1], err, string(out))
		}
	}
	return nil
}

func issue() error {
	dir := config.ACMEDirectory
	if isDryRun {
		dir = config.ACMEDryRunDirectory
	}

	acmeCl, err := acme.NewClient(dir,
		acme.WithUserAgentSuffix("fleetssl-dnsonly/"+version+
			" (https://github.com/letsencrypt-cpanel/letsencrypt-cpanel-dnsonly"),
		acme.WithHTTPClient(makeHTTPClientNoIPv6()))
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %v", err)
	}

	acmeKey, err := state.PrivateKey(dir)
	if err != nil {
		return fmt.Errorf("could not get ACME account private key: %v", err)
	}
	// Save early if we generated a private key
	if err := saveState(); err != nil {
		return err
	}

	log.Println("Creating/fetching ACME account ...")
	contact := []string{}
	if e := strings.TrimSpace(config.ACMEEmailAddress); e != "" {
		contact = append(contact, "mailto:"+e)
	}
	acct, err := acmeCl.NewAccount(acmeKey, false, true, contact...)
	if err != nil {
		return fmt.Errorf("failed to fetch/create ACME account: %v", err)
	}
	log.Printf("ACME Account URL: %s", acct.URL)

	// Submit an order
	log.Println("Creating order ...")
	order, err := acmeCl.NewOrderDomains(acct, config.CSRHostnames...)
	if err != nil {
		return fmt.Errorf("failed to create ACME order: %v", err)
	}
	log.Printf("Order URL: %s", order.URL)

	toks := map[string]string{}
	challs := []acme.Challenge{}

	// If this is a dry-run, we want to deactivate all pending and active
	// authorizations at the end of the run
	if isDryRun {
		defer func() {
			for _, u := range order.Authorizations {
				authz, err := acmeCl.FetchAuthorization(acct, u)
				if err != nil || (authz.Status != "valid" && authz.Status != "pending") {
					return
				}
				log.Printf("[DRY-RUN] Deactivating authorization %s", u)
				if _, err := acmeCl.DeactivateAuthorization(acct, u); err != nil {
					log.Printf("[DRY-RUN] Couldn't deactivate authorization %s: %v", u, err)
				}
			}
		}()
	}

	// Gather the challenges
	for _, authzURL := range order.Authorizations {
		authz, err := acmeCl.FetchAuthorization(acct, authzURL)
		if err != nil {
			return fmt.Errorf("failed to fetch authz %s: %v", authzURL, err)
		}

		chal, ok := authz.ChallengeMap[acme.ChallengeTypeHTTP01]
		if !ok {
			return fmt.Errorf("authz %s had no HTTP-01 challenge", authzURL)
		}
		if chal.Status != "pending" {
			continue
		}
		challs = append(challs, chal)
		toks[chal.Token] = chal.KeyAuthorization
	}

	// Spin up a standalone web server to fulfil our challenges
	log.Printf("Starting webserver on :%d", config.ListenPort)
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(config.ListenPort))
	if err != nil {
		return fmt.Errorf("Failed to listen on port %d: %v", config.ListenPort, err)
	}
	defer listener.Close()
	const pathPrefix = "/.well-known/acme-challenge/"
	go func() {
		if err := http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			if !strings.HasPrefix(p, pathPrefix) {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			tok := strings.TrimPrefix(p, pathPrefix)
			keyAuthz, ok := toks[tok]
			if !ok {
				http.Error(w, "Unknown challenge", http.StatusUnauthorized)
			}
			log.Printf("[WEB] Responding to %v/%s for %s",
				r.RemoteAddr, r.Header.Get("user-agent"), r.URL.Path)
			fmt.Fprint(w, keyAuthz)
		})); err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Op == "accept" {
				return
			}
			log.Printf("HTTP server stopped: %v, %T", err, err)
		}
	}()

	// Respond to each challenge
	log.Println("Responding to challenges ...")
	for _, chall := range challs {
		if _, err := acmeCl.UpdateChallenge(acct, chall); err != nil {
			return fmt.Errorf("responding to challenge %s failed: %v", chall.URL, err)
		}
	}

	// Generate a CSR
	log.Println("Generating CSR ...")
	signer, err := getOrCreateCertificateKey()
	if err != nil {
		return fmt.Errorf("could not acquire certificate private key: %v", err)
	}
	signerDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return fmt.Errorf("could not marshal certificate private key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		PublicKey: signer.Public(),
		Subject:   pkix.Name{CommonName: config.CSRHostnames[0]},
		DNSNames:  config.CSRHostnames,
	}, signer)
	if err != nil {
		return fmt.Errorf("could not generate CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("could not parse CSR: %v", err)
	}

	// Issue the certificate and download it
	log.Println("Finishing order ...")
	order, err = acmeCl.FinalizeOrder(acct, order, csr)
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %v", err)
	}

	// Downloading and saving the certificate is not required
	// for a dry-run.
	if isDryRun {
		log.Println("[DRY-RUN] Dry-run succeeded. Not downloading or installing the certificates.")
		return nil
	}

	log.Println("Downloading certificates ...")
	certs, err := acmeCl.FetchCertificates(acct, order.Certificate)
	if err != nil {
		return fmt.Errorf("failed to download certificates: %v", err)
	}

	chainPEM := make([]byte, 0)
	for _, crt := range certs {
		chainPEM = append(chainPEM, derToPEM(crt.Raw, "CERTIFICATE")...)
	}

	state.CertificateChain = chainPEM
	state.CertificatePrivateKey = signerDER
	state.needsPersist = true

	log.Println("Saving certificates to disk ...")
	if err := saveState(); err != nil {
		return fmt.Errorf("failed to save issued certificate: %v", err)
	}

	return nil
}

// checkNeedsToIssue determines whether we need to issue/renew the certificate,
// and additionally reports the reason if so.
func checkNeedsToIssue() (bool, string) {
	if len(state.CertificateChain) == 0 {
		return true, "no existing certificate exists"
	}

	// This ensures the private key and certificate are matching. The key was
	// saved in PKCS#8, the chain was saved in PEM.
	cert, err := tls.X509KeyPair(state.CertificateChain, derToPEM(state.CertificatePrivateKey, "PRIVATE KEY"))
	if err != nil {
		return true, fmt.Sprintf("failed to load existing key/cert pair: %v", err)
	}

	// Verify the chain itself for each DNS name we need
	chain := []*x509.Certificate{}
	for i, c := range cert.Certificate {
		parsed, err := x509.ParseCertificate(c)
		if err != nil {
			return true, fmt.Sprintf("failed to parse certificate #%d in chain: %v", i, err)
		}
		chain = append(chain, parsed)
	}
	if err := verifyChain(chain, config.CSRHostnames); err != nil {
		return true, fmt.Sprintf("failed to verify existing certificate: %v", err)
	}

	if isDryRun {
		return true, "dry-run was requested"
	}
	if isReinstall {
		return true, "certificate reinstall was requested"
	}

	return false, "certificate is valid and not expiring soon"
}

// verifyChain ensures that the existing certificate chain in the state
// is valid for all of the domain names that are requested in the config.
// This checks trustworthiness, validity for names and validity period.
// Validity period is evaluated 31 (default) days in the future to leave
// some time for renewal.
func verifyChain(chain []*x509.Certificate, dnsNames []string) error {
	if len(chain) == 0 {
		return errors.New("chain was empty")
	}

	intermediates := x509.NewCertPool()
	if len(chain) > 0 {
		for _, i := range chain[1:] {
			intermediates.AddCert(i)
		}
	}

	// If this is a dry-run, we need to explicitly trust the issuer
	var roots *x509.CertPool
	if isDryRun {
		roots = intermediates
	}

	leaf := chain[0]
	renewAt := time.Now().Add(24 * config.RenewalCutoff * time.Hour)

	for _, name := range dnsNames {
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       name,
			Intermediates: intermediates,
			CurrentTime:   renewAt,
			Roots:         roots,
		}); err != nil {
			return fmt.Errorf("certificate did not verify with name %s: %v", name, err)
		}
	}

	return nil
}

func getOrCreateCertificateKey() (crypto.Signer, error) {
	var signer crypto.Signer
	var err error

	if len(state.CertificatePrivateKey) > 0 {
		pk, err := x509.ParsePKCS8PrivateKey(state.CertificatePrivateKey)
		if err != nil {
			log.Printf("Couldn't read existing certificate private key, will generate a new one")
		} else {
			asSigner, ok := pk.(crypto.Signer)
			if !ok {
				log.Printf("Existing CSR key is not suitable, will generate a new one: %T", pk)
			}
			signer = asSigner
		}
	}
	if signer == nil {
		signer, err = newPrivateKey(config.CSRKeySpec)
		if err != nil {
			return nil, fmt.Errorf("failed to read or generate new CSR private key: %v", err)
		}
	}
	return signer, nil
}

// newPrivateKey generates a private key based on the provided key spec,
// which is in the format of alg:keySize. Supported algorithms are RSA
// and ECDSA.
func newPrivateKey(keySpec string) (crypto.Signer, error) {
	spec := strings.Split(strings.TrimSpace(keySpec), ":")
	if len(spec) != 2 {
		return nil, fmt.Errorf("invalid keyspec: %s", keySpec)
	}

	var err error
	var signer crypto.Signer

	switch strings.ToLower(spec[0]) {
	case "rsa":
		keySize, err := strconv.Atoi(spec[1])
		if err != nil {
			return nil, fmt.Errorf("could not parse keyspec key size %s: %v", spec[1], err)
		}
		signer, err = rsa.GenerateKey(rand.Reader, keySize)
	case "ecdsa":
		var curve elliptic.Curve
		switch spec[1] {
		case "224":
			curve = elliptic.P224()
		case "256":
			curve = elliptic.P256()
		case "384":
			curve = elliptic.P384()
		case "521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("ecdsa size is not available: %s", spec[1])
		}
		signer, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, fmt.Errorf("key alg is not implemented: %s", spec[0])
	}

	if err != nil {
		return nil, fmt.Errorf("error generating key: %v", err)
	}
	return signer, nil
}

func derToPEM(asn1Data []byte, pemType string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: asn1Data,
	})
}

func (sf *stateFile) PrivateKey(acmeDirectory string) (crypto.Signer, error) {
	if sf.ACMEAccountKeys == nil {
		sf.ACMEAccountKeys = map[string][]byte{}
	}

	// We may have an existing ACME account private key
	asDER, ok := sf.ACMEAccountKeys[acmeDirectory]
	if ok {
		pk, err := x509.ParsePKCS8PrivateKey(asDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse existing private key: %v", err)
		}
		if signer, ok := pk.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("failed to use existing private key of type %T", pk)
	}

	// Or we need to generate a new one
	log.Printf("Generating new %s private key for %s", config.ACMEKeySpec, acmeDirectory)
	signer, err := newPrivateKey(config.ACMEKeySpec)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new %s ACME account private key: %v", config.ACMEKeySpec, err)
	}

	asDER, err = x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ACME account private key: %v", err)
	}

	sf.ACMEAccountKeys[acmeDirectory] = asDER
	sf.needsPersist = true

	return signer, nil
}

// loadConfig loads the prefixed configuration parameters from confPath,
// and sets each one using environment variables. This is similar to
// /etc/default/-type service envfiles, but without shell evaluation.
// You can always pass parameters as environment variables, but those
// present in confPath will take precedence.
func loadConfig() error {
	// Load the env vars from file
	f, err := os.Open(confPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to read config envfile: %v", err)
	} else if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			t := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(t, "FLEETSSL_DNSONLY_") {
				continue
			}
			delim := strings.Index(t, "=")
			if delim == -1 || len(t)-1 == delim {
				continue
			}
			if err := os.Setenv(t[:delim], t[delim+1:]); err != nil {
				return fmt.Errorf("failed to set config parameter (%s): %v", t, err)
			}
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("error reading config envfile: %v", err)
		}
	}

	// And then apply the env vars
	config.ACMEDirectory = envOrDefault("ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory")
	config.ACMEDryRunDirectory = envOrDefault("ACME_DIRECTORY", "https://acme-staging-v02.api.letsencrypt.org/directory")
	config.ACMEKeySpec = envOrDefault("ACME_KEY_TYPE", "ecdsa:256")
	config.ACMEEmailAddress = envOrDefault("ACME_EMAIL_ADDRESS", "")
	config.CSRKeySpec = envOrDefault("CERT_KEY_TYPE", "rsa:2048")

	hostnames := strings.Split(envOrDefault("CERT_HOSTNAMES", ""), ",")
	if len(hostnames) == 0 || hostnames[0] == "" {
		hn, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("could not determine this server's hostname: %v", err)
		}
		config.CSRHostnames = []string{hn}
	} else {
		config.CSRHostnames = hostnames
	}

	renewCutoff, err := strconv.ParseInt(envOrDefault("RENEWAL_CUTOFF", "31"), 10, 64)
	if err != nil {
		return fmt.Errorf("could not understand RENEWAL_CUTOFF: %v", err)
	}
	config.RenewalCutoff = time.Duration(renewCutoff)

	listenPort, err := strconv.Atoi(strings.TrimSpace(envOrDefault("LISTEN_PORT", "80")))
	if err != nil {
		return fmt.Errorf("could not parse listen port: %v", err)
	}
	config.ListenPort = listenPort

	// Show the user what they have changed
	for _, v := range os.Environ() {
		if strings.HasPrefix(v, "FLEETSSL_DNSONLY_") {
			log.Printf("[CONFIG] %s", v)
		}
	}

	return nil
}

// loadState loads the state from statePath (expects a JSON-encoded file)
func loadState() error {
	stat, err := os.Stat(statePath)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("couldn't check status of state file: %v", err)
	}
	if perm := stat.Mode().Perm(); perm != 0600 {
		return fmt.Errorf("unsafe permissions on %s: %o, refusing to run", statePath, perm)
	}
	f, err := os.Open(statePath)
	if err != nil {
		return fmt.Errorf("could not open state file: %v", err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(state); err != nil {
		return fmt.Errorf("could not parse state file: %v", err)
	}
	return nil
}

// saveState persists the state only if it is neccessary
func saveState() error {
	if !state.needsPersist {
		return nil
	}

	f, err := os.OpenFile(statePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("could not open state file for saving: %v", err)
	}

	if err := json.NewEncoder(f).Encode(state); err != nil {
		return fmt.Errorf("could not write state file: %v", err)
	}

	return nil
}

func envOrDefault(name, defaultValue string) string {
	if s := strings.TrimSpace(os.Getenv("FLEETSSL_DNSONLY_" + name)); s != "" {
		return s
	}
	return defaultValue
}

func makeHTTPClientNoIPv6() *http.Client {
	dc := &net.Dialer{
		DualStack: false,
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, net, addr string) (net.Conn, error) {
				return dc.DialContext(ctx, "tcp4", addr)
			},
		},
		Timeout: 60 * time.Second,
	}
}
