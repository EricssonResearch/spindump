package aggregate

import (
	"strconv"
	"errors"
	"log"

	"github.com/EricssonResearch/spindump/go/aggregator/internal/iofmt"
	"github.com/EricssonResearch/spindump/go/aggregator/internal/statistics"
)

//----------Type Definitions----------------------------------------------------

type SessionGroup struct {
	sessions map[string]*Session
	nObservers int
	smoothing bool
}

type Session struct {
  ClientId  string
  ServerId  string
  Type      string

	observers []observer
	outputFormat iofmt.C3Sequence
	cnt int
	cntMax int
}

type observer struct {
  LeftRtt uint
  RightRtt uint
  FullRtt uint
}

type sessionId struct {
  Id   string
  Type string
}

//----------Public Functions----------------------------------------------------

func NewSessionGroup(n int, smth bool) SessionGroup {
	return SessionGroup{
		sessions: make(map[string]*Session),
		nObservers: n,
		smoothing: smth,
	}
}

func (sg* SessionGroup) FormatSession(sid string) (iofmt.C3Sequence, error) {
	s, ok := sg.sessions[sid]
  if !ok {
		return nil, errors.New("No such session: " + sid)
	}
	return s.format(), nil
}

func (sg* SessionGroup) Ids() []sessionId {
	var sids []sessionId
  for id, sess := range sg.sessions {
    sids = append(sids, sessionId{Id: id, Type: sess.Type})
  }
	return sids
}

func (sg* SessionGroup) NewEvent(ev iofmt.Event, obs string) {
	s, ok := sg.sessions[ev.Session]
  if !ok {
    s = newSession(ev, sg.nObservers, sg.smoothing)
    log.Printf("New session %s", ev.Session)
    sg.sessions[ev.Session] = s
  }
	if ev.Event == "measurement" {
    s.addSample(ev, obs, sg.smoothing)
  }
}

//----------Private Functions---------------------------------------------------

func newSession(e iofmt.Event, n int, smoothing bool) *Session {
	cm := 1
	if smoothing {
		cm = 63 // TODO: make configurable
	}
	return &Session{
		Type: e.Type,
		outputFormat: make(iofmt.C3Sequence),
		observers: make([]observer, n),
		cnt: 0,
		cntMax: cm,
	}
}

func (s* Session) format() iofmt.C3Sequence {
	left := s.observers[0].LeftRtt
	full := s.observers[0].FullRtt
	out := []iofmt.LabeledRtt{iofmt.LabeledRtt{Label: "C-0", Rtt: left}}

	for i := 1; i < len(s.observers); i++ {
		var rtt uint
		rtt = 0
		if s.observers[i].LeftRtt != 0 {
			rtt = s.observers[i].LeftRtt - s.observers[i-1].LeftRtt
		}
		label := strconv.Itoa(i-1) + "-" + strconv.Itoa(i)
		out = append(out, iofmt.LabeledRtt{Label: label, Rtt: rtt})
	}
	right := s.observers[len(s.observers)-1].RightRtt
	out = append(out, iofmt.LabeledRtt{Label: strconv.Itoa(len(s.observers)-1) + "-S", Rtt: right})
	out = append(out, iofmt.LabeledRtt{Label: "Full", Rtt: full})

	s.outputFormat.Add(out)

	return s.outputFormat
}

func (s* Session) addSample(event iofmt.Event, obsid string, smth bool) {
	id, err := strconv.Atoi(obsid)
	if err != nil {
		panic(err)
	}
	s.observers[id].addSample(event, smth)

	s.cnt++
	if s.cnt > s.cntMax {
		s.format()
		s.cnt = 0
	}
}

func (o* observer) addSample(event iofmt.Event, smoothing bool) {
  if event.Left_rtt != 0 {
		if smoothing {
			o.LeftRtt = statistics.Ewma(o.LeftRtt, event.Left_rtt)
		} else {
			o.LeftRtt = event.Left_rtt
		}
  }
  if event.Right_rtt != 0 {
		if smoothing {
			o.RightRtt = statistics.Ewma(o.RightRtt, event.Right_rtt)
		} else {
			o.RightRtt = event.Right_rtt
		}
	}
  if event.Full_rtt_initiator != 0 {
		if smoothing {
    	o.FullRtt = statistics.Ewma(o.FullRtt, event.Full_rtt_initiator)
		} else {
			o.FullRtt = event.Full_rtt_initiator
		}
  }
}
