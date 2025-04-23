package managerapi

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	managerdb "github.com/spiffe/tornjak/pkg/manager/db"
)

const (
	keyShowLen  int = 40
	certShowLen int = 50
)

type Server struct {
	listenAddr string
	db         managerdb.ManagerDB
}

// Handle preflight checks
func corsHandler(f func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			cors(w, r)
			return
		} else {
			f(w, r)
		}
	}
}

func cors(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=ascii")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,access-control-allow-origin, access-control-allow-headers")
	w.WriteHeader(http.StatusOK)
}

func retError(w http.ResponseWriter, emsg string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=ascii")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,access-control-allow-origin, access-control-allow-headers")
	http.Error(w, emsg, status)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// apiServerProxyFunc returns an http.HandlerFunc that proxies a request to the
// given Tornjak / SPIRE API path, honouring the per-server TLS / mTLS settings
// stored in the manager DB.
func (s *Server) apiServerProxyFunc(apiPath, apiMethod string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serverName := mux.Vars(r)["server"]

		// 1. Resolve server entry & client
		sinfo, client, err := s.prepareServerClient(serverName)
		if err != nil {
			retError(w, fmt.Sprintf("Error preparing client: %v", err), http.StatusBadRequest)
			return
		}

		// 2. Build outbound request
		req, err := buildProxyRequest(r, sinfo.Address, apiPath, apiMethod)
		if err != nil {
			retError(w, fmt.Sprintf("Error creating request: %v", err), http.StatusBadRequest)
			return
		}

		// 3. Perform request & stream response
		if err := forwardResponse(w, client, req); err != nil {
			retError(w, fmt.Sprintf("Error forwarding response: %v", err), http.StatusBadGateway)
		}
	}
}

// forwardResponse executes the outbound request and streams headers/body back
// to the original client, preserving status codes.
func forwardResponse(w http.ResponseWriter, client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

// prepareServerClient fetches server metadata from the DB and returns both the
// metadata and a configured *http.Client.
func (s *Server) prepareServerClient(name string) (*managerdb.ServerInfo, *http.Client, error) {
	sinfo, err := s.db.GetServer(name)
	if err != nil {
		return nil, nil, fmt.Errorf("DB lookup failed: %w", err)
	}

	// Emit concise debug info (unchanged logic, but extracted for clarity)
	debugServerInfo(sinfo)

	client, err := sinfo.HttpClient()
	if err != nil {
		return nil, nil, err
	}
	return sinfo, client, nil
}

// buildProxyRequest constructs a new outbound request that preserves the
// incoming body and headers but targets the SPIRE/Tornjak endpoint.
func buildProxyRequest(src *http.Request, baseAddr, apiPath, method string) (*http.Request, error) {
	targetURL := strings.TrimSuffix(baseAddr, "/") + apiPath

	req, err := http.NewRequest(method, targetURL, src.Body)
	if err != nil {
		return nil, err
	}

	// Forward content-type & auth headers if present
	for k, v := range src.Header {
		// Typical allow-list; extend as needed
		if k == "Content-Type" || k == "Authorization" {
			req.Header[k] = v
		}
	}
	return req, nil
}
// ---------- helpers ----------

func debugServerInfo(sinfo *managerdb.ServerInfo) {
	trim := func(s string, max int) string {
		if len(s) <= max {
			return s
		}
		return "\n..." + s[len(s)-max:]
	}
	fmt.Printf("Name:%s  Address:%s  TLS:%t  mTLS:%t\n",
		sinfo.Name, sinfo.Address, sinfo.TLS, sinfo.MTLS)
	if sinfo.TLS {
		fmt.Printf("CA:%s\n", trim(string(sinfo.CA), certShowLen))
	}
	if sinfo.MTLS {
		fmt.Printf("Cert:%s\nKey:%s\n",
			trim(string(sinfo.Cert), certShowLen),
			trim(string(sinfo.Key), keyShowLen))
	}
}

// spaHandler implements the http.Handler interface, so we can use it
// to respond to HTTP requests. The path to the static directory and
// path to the index file within that static directory are used to
// serve the SPA in the given static directory.
type spaHandler struct {
	staticPath string
	indexPath  string
}

// ServeHTTP inspects the URL path to locate a file within the static dir
// on the SPA handler. If a file is found, it will be served. If not, the
// file located at the index path on the SPA handler will be served. This
// is suitable behavior for serving an SPA (single page application).
func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// get the absolute path to prevent directory traversal
	path, err := filepath.Abs(r.URL.Path)
	if err != nil {
		// if we failed to get the absolute path respond with a 400 bad request
		// and stop
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// prepend the path with the path to the static directory
	path = filepath.Join(h.staticPath, path)

	// check whether a file exists at the given path
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		// file does not exist, serve index.html
		http.ServeFile(w, r, filepath.Join(h.staticPath, h.indexPath))
		return
	} else if err != nil {
		// if we got an error (that wasn't that the file doesn't exist) stating the
		// file, return a 500 internal server error and stop
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// otherwise, use http.FileServer to serve the static dir
	http.FileServer(http.Dir(h.staticPath)).ServeHTTP(w, r)
}

// HandleRequests wires up every HTTP route and blocks in ListenAndServe.
func (s *Server) HandleRequests() {
	r := mux.NewRouter()

	// --- manager API --------------------------------------------------------
	addRoutes(r, map[string]http.HandlerFunc{
		"/manager-api/server/list":     s.serverList,
		"/manager-api/server/register": s.serverRegister,
	})

	// --- SPIRE core ---------------------------------------------------------
	addSpireRoutes := func(prefix string) {
		addProxy(r, prefix+"/healthcheck/{server:.*}",  "/api/v1/spire/healthcheck", http.MethodGet)
		addProxy(r, prefix+"/serverinfo/{server:.*}",   "/api/v1/spire/serverinfo",  http.MethodGet)

		addProxy(r, prefix+"/entry/list/{server:.*}",   "/api/v1/spire/entries",     http.MethodGet)
		addProxy(r, prefix+"/entry/create/{server:.*}", "/api/v1/spire/entries",     http.MethodPost)
		addProxy(r, prefix+"/entry/delete/{server:.*}", "/api/v1/spire/entries",     http.MethodDelete)

		addProxy(r, prefix+"/agent/list/{server:.*}",          "/api/v1/spire/agents",           http.MethodGet)
		addProxy(r, prefix+"/agent/delete/{server:.*}",        "/api/v1/spire/agents",           http.MethodDelete)
		addProxy(r, prefix+"/agent/ban/{server:.*}",           "/api/v1/spire/agents/ban",       http.MethodPost)
		addProxy(r, prefix+"/agent/createjointoken/{server:.*}","/api/v1/spire/agents/jointoken",http.MethodPost)
	}
	addSpireRoutes("/manager-api")

	// --- Tornjak extensions -------------------------------------------------
	addTornjakRoutes := func(prefix string) {
		addProxy(r, prefix+"/serverinfo/{server:.*}",               "/api/v1/tornjak/serverinfo", http.MethodGet)

		addProxy(r, prefix+"/selectors/register/{server:.*}",       "/api/v1/tornjak/selectors",  http.MethodPost)
		addProxy(r, prefix+"/selectors/list/{server:.*}",           "/api/v1/tornjak/selectors",  http.MethodGet)
		addProxy(r, prefix+"/agents/list/{server:.*}",              "/api/v1/tornjak/agents",     http.MethodGet)

		addProxy(r, prefix+"/clusters/create/{server:.*}",          "/api/v1/tornjak/clusters",   http.MethodPost)
		addProxy(r, prefix+"/clusters/edit/{server:.*}",            "/api/v1/tornjak/clusters",   http.MethodPatch)
		addProxy(r, prefix+"/clusters/list/{server:.*}",            "/api/v1/tornjak/clusters",   http.MethodGet)
		addProxy(r, prefix+"/clusters/delete/{server:.*}",          "/api/v1/tornjak/clusters",   http.MethodDelete)
	}
	addTornjakRoutes("/manager-api/tornjak")

	// --- static SPA ---------------------------------------------------------
	spa := spaHandler{staticPath: "ui-manager", indexPath: "index.html"}
	r.PathPrefix("/").Handler(spa)

	fmt.Printf("Manager API listening on %s …\n", s.listenAddr)
	log.Fatal(http.ListenAndServe(s.listenAddr, r))
}

//
// ---------- tiny helpers  --------------
//

// addRoutes registers simple (non-proxy) handlers and wraps them in CORS.
func addRoutes(r *mux.Router, routes map[string]http.HandlerFunc) {
	for path, h := range routes {
		r.HandleFunc(path, corsHandler(h))
	}
}

// addProxy is a convenience shim around apiServerProxyFunc + CORS.
func (s *Server) addProxy(r *mux.Router, pattern, apiPath, method string) {
	r.HandleFunc(pattern, corsHandler(s.apiServerProxyFunc(apiPath, method)))
}

/*

func main() {
  rtr := mux.NewRouter()
  rtr.HandleFunc("/number/{id:[0-9]+}", pageHandler)
  http.Handle("/", rtr)
  http.ListenAndServe(PORT, nil)
}
*/

// NewManagerServer returns a new manager server, given a listening address for the
// server, and a DB connection string
func NewManagerServer(listenAddr, dbString string) (*Server, error) {
	db, err := managerdb.NewLocalSqliteDB(dbString)
	if err != nil {
		return nil, err
	}
	return &Server{
		listenAddr: listenAddr,
		db:         db,
	}, nil
}

func (s *Server) serverList(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Endpoint Hit: Server List")

	buf := new(strings.Builder)

	n, err := io.Copy(buf, r.Body)
	if err != nil {
		emsg := fmt.Sprintf("Error parsing data: %v", err.Error())
		retError(w, emsg, http.StatusBadRequest)
		return
	}
	data := buf.String()

	var input ListServersRequest
	if n == 0 {
		input = ListServersRequest{}
	} else {
		err := json.Unmarshal([]byte(data), &input)
		if err != nil {
			emsg := fmt.Sprintf("Error parsing data: %v", err.Error())
			retError(w, emsg, http.StatusBadRequest)
			return
		}
	}

	ret, err := s.ListServers(input)
	if err != nil {
		emsg := fmt.Sprintf("Error: %v", err.Error())
		retError(w, emsg, http.StatusBadRequest)
		return
	}
	cors(w, r)

	je := json.NewEncoder(w)
	err = je.Encode(ret)

	if err != nil {
		emsg := fmt.Sprintf("Error: %v", err.Error())
		retError(w, emsg, http.StatusBadRequest)
		return
	}
}

func (s *Server) serverRegister(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Endpoint Hit: Server Create")

	buf := new(strings.Builder)

	n, err := io.Copy(buf, r.Body)
	if err != nil {
		emsg := fmt.Sprintf("Error parsing data: %v", err.Error())
		retError(w, emsg, http.StatusBadRequest)
		return
	}
	data := buf.String()

	var input RegisterServerRequest
	if n == 0 {
		input = RegisterServerRequest{}
	} else {
		err := json.Unmarshal([]byte(data), &input)
		if err != nil {
			emsg := fmt.Sprintf("Error parsing data: %v", err.Error())
			retError(w, emsg, http.StatusBadRequest)
			return
		}
	}

	err = s.RegisterServer(input)
	if err != nil {
		emsg := fmt.Sprintf("Error: %v", err.Error())
		retError(w, emsg, http.StatusBadRequest)
		return
	}

	cors(w, r)
	_, err = w.Write([]byte("SUCCESS"))

	if err != nil {
		emsg := fmt.Sprintf("Error: %v", err.Error())
		retError(w, emsg, http.StatusBadRequest)
		return
	}
}
