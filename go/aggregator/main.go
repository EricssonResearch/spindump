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
  "github.com/EricssonResearch/spindump/go/aggregator/internal/iofmt"
)

var sessions aggregate.SessionGroup

func getSessions(w http.ResponseWriter, _ *http.Request) {
  json.NewEncoder(w).Encode(sessions.Ids())
}

func getSession(w http.ResponseWriter, r *http.Request) {
  var sessId = mux.Vars(r)["session"]
  s, err := sessions.FormatSession(sessId)
  if err != nil {
    panic(err)
  }
  json.NewEncoder(w).Encode(s)
}

func addEvent(w http.ResponseWriter, r *http.Request) {
  body, err :=  ioutil.ReadAll(r.Body)
  if err != nil {
    panic(err)
  }

  var sender = mux.Vars(r)["id"]

  var event iofmt.Event
  err = json.Unmarshal(body, &event)
  if err != nil {
    panic(err)
  }
  sessions.NewEvent(event, sender)
}

func commonHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Add("Access-Control-Allow-Origin","*")
        next.ServeHTTP(w, r)
    })
}

func main() {

  sAddr := flag.String("bind", "0.0.0.0:5040", "Server address")
  nInst := flag.Int("reporters", 1, "N spindump instances")
  smth := flag.Bool("rtt-smoothing", true, "RTT smoothing on/off")
  flag.Parse()

  sessions = aggregate.NewSessionGroup(*nInst, *smth)

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
  signal.Notify(c, os.Interrupt)

  <-c

  ctx, cancel := context.WithTimeout(context.Background(), time.Second * 1)
  defer cancel()
  srv.Shutdown(ctx)
  log.Println("shutting down")
  os.Exit(0)
}
