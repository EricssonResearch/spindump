package main
import (
  "encoding/json"
  "net/http"
  "io/ioutil"
  "log"
)

// representation of spindump json event
type spindump_event struct {
  Type                string
  Event               string
  Addrs               []string
  Session             string
  Ts                  uint
  Left_rtt            uint
  Right_rtt           uint
  Sum_rtt             uint
  Full_rtt_initiator  uint
  Full_rtt_responder  uint
  ECT0                uint
  ECT1                uint
  CE                  uint
}

// We wont store entire event structs...
type session struct {
  Events []spindump_event
}

// Let's do smart things
func (s *session) addEvent(ev spindump_event) {
  s.Events = append(s.Events, ev)
}

func receiveEvent(w http.ResponseWriter, r *http.Request, s *session) {
  body, err :=  ioutil.ReadAll(r.Body)
  if err != nil {
    panic(err)
  }
  log.Println(string(body))
  var event spindump_event
  err = json.Unmarshal(body, &event)
  if err != nil {
    panic(err)
  }
  s.addEvent(event)
  log.Println("Added event!")
}

func main() {
  var s session
  recvEventFunc := func(w http.ResponseWriter, r *http.Request) {
    receiveEvent(w, r, &s)
  }
  http.HandleFunc("/data/foo", recvEventFunc)
  if err := http.ListenAndServe(":5040", nil); err != nil {
    panic(err)
  }
}
