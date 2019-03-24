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
  Full_rtt_initiator  uint
  Full_rtt_responder  uint
  ECT0                uint
  ECT1                uint
  CE                  uint
}

type rtt_sample struct {
  FullRtt   uint
  LeftRtt   uint
  RightRtt  uint
  Timestamp uint
}

type observer struct {
  RttSamples  []rtt_sample
}

type session struct {
  ClientId  string
  ServerId  string
  Observers map[string]*observer
}

// Let's do smart things
func (s *session) newEvent(ev *spindump_event, obs string) {
  _, ok := s.Observers[obs]
  if !ok {
    log.Printf("New Spindump Observer! %s \n", obs)
    s.Observers[obs] = &observer{}
  }

  if ev.Event == "measurement" {
    var rs rtt_sample
    rs.FullRtt = ev.Full_rtt_initiator
    rs.LeftRtt = ev.Left_rtt
    rs.RightRtt = ev.Right_rtt
    s.Observers[obs].addSample(rs)
    log.Printf("New measurement event %+v", rs)
  }
}

func (o *observer) addSample(s rtt_sample) {
  o.RttSamples = append(o.RttSamples, s)
}
// todo: implement goroutine and channel so that the http listener process performs minimal work
func receiveEvent(w http.ResponseWriter, r *http.Request, sender string, s *map[string]session) {
  body, err :=  ioutil.ReadAll(r.Body)
  if err != nil {
    panic(err)
  }
  log.Println(string(body)) // todo: loglevels
  var event spindump_event
  err = json.Unmarshal(body, &event)
  if err != nil {
    panic(err)
  }
  sess, ok := (*s)[event.Session]
  if !ok {
    sess = session{ClientId: event.Addrs[0], ServerId: event.Addrs[1], Observers: make(map[string]*observer)}
    (*s)[event.Session] = sess
  }
  sess.newEvent(&event, sender)
}

func rcvFunc(sessions *map[string]session, senderId string) func(http.ResponseWriter, *http.Request) {
  return func(w http.ResponseWriter, r *http.Request) {
    receiveEvent(w, r, senderId, sessions)
  }
}

// todo: move data store and functionality to appropriate package and files
func main() {
  var sessions map[string]session
  sessions = make(map[string]session)
  senders := []string{"sd1", "sd2"} // configure the spindump senders we accept events from

  for _, snd := range senders {
    http.HandleFunc("/data/"+snd, rcvFunc(&sessions, snd))
  }

  if err := http.ListenAndServe(":5040", nil); err != nil {
    panic(err)
  }
}
