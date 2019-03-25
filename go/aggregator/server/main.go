package main
import (
  "encoding/json"
  "net/http"
  "io/ioutil"
  "log"
)

const leftSd  = "sd1"
const rightSd = "sd2"

// representation of spindump json event
type spindump_event struct {
  Type                string
  Event               string
  Addrs               []string
  Session             string
  Ts                  string
  Left_rtt            uint
  Right_rtt           uint
  Full_rtt_initiator  uint
  Full_rtt_responder  uint
  ECT0                uint
  ECT1                uint
  CE                  uint
  Packets             uint
  Bytes               uint
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

// type session struct {
//   ClientId  string
//   ServerId  string
//   Type      string
//   Observers map[string]*observer
// }

type session_id struct {
  Id   string
  Type string
}

type RttSample struct {
  Timestamp      string
  LeftRtt        uint
  RightRtt       uint
  FullRtt        uint
  MidRtt         uint
  LastObserver   string
  SampleComplete bool
}

type Session struct {
  Type    string
  Samples []*RttSample
}

type SessionOutputFormat struct {
  Timestamps []string
  LeftRtts   []uint
  RightRtts  []uint
  MidRtts    []uint
  FullRtts   []uint
}

func (s* Session) outputFormat() SessionOutputFormat {
  var ret SessionOutputFormat
  for _, s := range s.Samples {
    ret.Timestamps = append(ret.Timestamps, s.Timestamp)
    ret.LeftRtts = append(ret.LeftRtts, s.LeftRtt)
    ret.RightRtts = append(ret.RightRtts, s.RightRtt)
    ret.MidRtts = append(ret.MidRtts, s.MidRtt)
    ret.FullRtts = append(ret.FullRtts, s.FullRtt)
  }
  //  log.Println(ret)
  return ret
}

// func (s* Session) addSample(timeStamp string, fullRtt uint, leftRtt uint, rightRtt uint, observer string) {
//
// }
func (s* Session) addSample(timeStamp string,
                            fullRtt uint,
                            leftRtt uint,
                            rightRtt uint,
                            observer string) {
  l := len(s.Samples)
  log.Printf("adding sample from %s", observer)
  if l == 0 || s.Samples[len(s.Samples)-1].SampleComplete {
    s.Samples = append(s.Samples, &RttSample{
      Timestamp: timeStamp,
      LeftRtt: leftRtt,
      RightRtt: rightRtt,
      FullRtt: fullRtt,
      LastObserver: observer,
      SampleComplete: false,
    })
    // log.Printf("adding first sample, len %d", len(s.Samples))
  } else {
    last := s.Samples[len(s.Samples)-1]
    if observer == last.LastObserver {
      if fullRtt != 0 {
        last.FullRtt = fullRtt
      }
      if leftRtt != 0 {
        last.LeftRtt = leftRtt
      }
      if rightRtt != 0 {
        last.RightRtt = leftRtt
      }
    } else if observer == rightSd {
      if rightRtt != 0 {
        last.RightRtt = rightRtt
        last.SampleComplete = true
      }
      if leftRtt != 0 && last.LeftRtt != 0 {
        last.MidRtt = leftRtt - last.LeftRtt
        if s.Type == "ICMP" {
          last.SampleComplete = true;
        }
      }
    } else if observer == leftSd {
      if leftRtt != 0 {
        last.LeftRtt = leftRtt
      }
      if rightRtt != 0 {
        last.SampleComplete = true;
      }
    }
  }
}

// Let's do smart things
func (s *Session) newEvent(ev *spindump_event, obs string) {
  if ev.Event == "measurement" {
    s.addSample(ev.Ts, ev.Full_rtt_initiator, ev.Left_rtt, ev.Right_rtt, obs)
  }
}

// func (o *observer) addSample(s rtt_sample) {
//   o.RttSamples = append(o.RttSamples, s)
// }
// todo: implement goroutine and channel so that the http listener process performs minimal work
func receiveEvent(w http.ResponseWriter, r *http.Request, sender string, s *map[string]*Session) {
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
    sess = &Session{Type: event.Type}
    log.Printf("New session %s", event.Session)
    (*s)[event.Session] = sess
    http.HandleFunc("/demo/"+event.Session, sndFunc(s, event.Session))
  }
  sess.newEvent(&event, sender)
}

func sndFunc(sessions *map[string]*Session, sessId string) func(http.ResponseWriter, *http.Request) {
  return func(w http.ResponseWriter, r *http.Request) {
    sess, _ := (*sessions)[sessId]
    w.Header().Add("Access-Control-Allow-Origin","*")
    json.NewEncoder(w).Encode(sess.outputFormat())
  }
}

func rcvFunc(sessions *map[string]*Session, senderId string) func(http.ResponseWriter, *http.Request) {
  return func(w http.ResponseWriter, r *http.Request) {
    receiveEvent(w, r, senderId, sessions)
  }
}

// todo: move data store and functionality to appropriate package and files
func main() {
  var sessions map[string]*Session
  sessions = make(map[string]*Session)
  senders := []string{"sd1", "sd2"} // configure the spindump senders we accept events from

  for _, snd := range senders {
    http.HandleFunc("/data/"+snd, rcvFunc(&sessions, snd))
  }

  sndSessFunc := func(w http.ResponseWriter, _ *http.Request) {
    var sids []session_id
    for id, sess := range sessions {
      sids = append(sids, session_id{Id: id, Type: sess.Type})
    }
    w.Header().Add("Access-Control-Allow-Origin","*")
    json.NewEncoder(w).Encode(sids)
    //io.WriteString(json.Marshal(sids))
  }
  http.HandleFunc("/demo", sndSessFunc)

  if err := http.ListenAndServe(":5040", nil); err != nil {
    panic(err)
  }
}
