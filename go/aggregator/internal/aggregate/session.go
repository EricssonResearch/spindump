package aggregate

import (
	"strconv"

	"github.com/EricssonResearch/spindump/go/aggregator/internal/format"
)

type Session struct {
  ClientId  string
  ServerId  string
  Type      string

	observers [nObservers]Observer
	outputFormat format.C3Sequence
	cnt int
}

func NewSession(e Event) *Session {
	return &Session{
		Type: e.Type,
		outputFormat: make(format.C3Sequence),
		cnt: 0,
	}
}

type SessionId struct {
  Id   string
  Type string
}

func (s* Session) OutputFormat() format.C3Sequence {
	left := s.observers[0].LeftRtt
	full := s.observers[0].FullRtt
	out := []format.LabeledRtt{format.LabeledRtt{Label: "C-0", Rtt: left}}

	for i := 1; i < len(s.observers); i++ {
		rtt := s.observers[i].LeftRtt - s.observers[i-1].LeftRtt
		label := strconv.Itoa(i-1) + "-" + strconv.Itoa(i)
		out = append(out, format.LabeledRtt{Label: label, Rtt: rtt})
	}
	right := s.observers[len(s.observers)-1].RightRtt
	out = append(out, format.LabeledRtt{Label: strconv.Itoa(len(s.observers)-1) + "-S", Rtt: right})
	out = append(out, format.LabeledRtt{Label: "Full", Rtt: full})

	s.outputFormat.Add(out)

	return s.outputFormat
}

func (s* Session) addSample(event Event, obsid string) {
	id, err := strconv.Atoi(obsid)
	if err != nil {
		panic(err)
	}
	s.observers[id].addSample(event)

	s.cnt++
	if s.cnt > 63 {
		s.OutputFormat()
		s.cnt = 0
	}
}

// Let's do smart things
func (s *Session) NewEvent(ev Event, obs string) {
  if ev.Event == "measurement" {
    s.addSample(ev, obs)
  }
}
