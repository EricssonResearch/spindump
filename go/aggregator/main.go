package main
import (
  "encoding/json"
  "net/http"
  "io/ioutil"
  "log"
  "flag"
  "time"
  "os"
  "context"
  "os/signal"

  "github.com/gorilla/mux"

  "github.com/EricssonResearch/spindump/go/aggregator/internal/aggregate"
)

var sessions map[string]*aggregate.Session

func getSessions(w http.ResponseWriter, _ *http.Request) {
  var sids []aggregate.SessionId
  for id, sess := range sessions {
    sids = append(sids, aggregate.SessionId{Id: id, Type: sess.Type})
  }
  json.NewEncoder(w).Encode(sids)
}

func getSession(w http.ResponseWriter, r *http.Request) {
  var sessId = mux.Vars(r)["session"]
  sess, _ := sessions[sessId]
  json.NewEncoder(w).Encode(sess.OutputFormat())
}

func addEvent(w http.ResponseWriter, r *http.Request) {
  body, err :=  ioutil.ReadAll(r.Body)
  if err != nil {
    panic(err)
  }

  var sender = mux.Vars(r)["id"]

  var event aggregate.Event
  err = json.Unmarshal(body, &event)
  if err != nil {
    panic(err)
  }

  sess, ok := sessions[event.Session]
  if !ok {
    sess = aggregate.NewSession(event)
    log.Printf("New session %s", event.Session)
    sessions[event.Session] = sess
  }
  sess.NewEvent(event, sender)
}

func commonHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Add("Access-Control-Allow-Origin","*")
        next.ServeHTTP(w, r)
    })
}

// todo: move data store and functionality to appropriate package and files
func main() {

  sessions = make(map[string]*aggregate.Session)

  sAddr := flag.String("bind", "0.0.0.0:5040", "Server address")
  flag.Parse()

  r := mux.NewRouter()
  r.HandleFunc("/data/{id:[0-9]+}", addEvent).Methods("POST")
  r.HandleFunc("/demo", getSessions).Methods("GET")
  r.HandleFunc("/demo/{session}", getSession).Methods("GET")
  r.Use(commonHeaders)

  srv := &http.Server{
    Addr:         *sAddr,
    WriteTimeout: time.Second * 1,
    ReadTimeout:  time.Second * 10,
    Handler: r,
  }

  go func() {
    if err := srv.ListenAndServe(); err != nil {
      log.Println(err)
    }
  }()

  c := make(chan os.Signal, 1)
  // We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
  signal.Notify(c, os.Interrupt)

  <-c

  ctx, cancel := context.WithTimeout(context.Background(), time.Second * 1)
  defer cancel()
  srv.Shutdown(ctx)
  log.Println("shutting down")
  os.Exit(0)
}
