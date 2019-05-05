package aggregate

const nObservers = 2 // TODO: Make proper config

type Observer struct {
  LeftRtt uint
  RightRtt uint
  FullRtt uint
}

func (o* Observer) addSample(event Event) {
  if event.Left_rtt != 0 {
		o.LeftRtt = ewma(o.LeftRtt, event.Left_rtt)
  }
  if event.Right_rtt != 0 {
		o.RightRtt = ewma(o.RightRtt, event.Right_rtt)
	}
  if event.Full_rtt_initiator != 0 {
    o.FullRtt = ewma(o.FullRtt, event.Full_rtt_initiator)
  }
  // if event.Full_rtt_responder != 0 {
	// 	o.FullRtt = ewma(o.FullRtt, event.Full_rtt_responder)
  // }
}

func ewma(a uint, s uint) uint {
	if a == 0 {
		return s
	}
	return s >> 4 + (a*15) >> 4
}
