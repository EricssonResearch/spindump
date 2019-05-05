package format

type LabeledRtt struct {
	Label string
	Rtt uint
}

type C3Sequence map[string][]uint

func (s* C3Sequence) Add (lrs []LabeledRtt) {
	for _, lr := range lrs {
		_, ok := (*s)[lr.Label]
	  if !ok {
	    (*s)[lr.Label] = []uint{lr.Rtt}
		} else {
		(*s)[lr.Label] = append((*s)[lr.Label], lr.Rtt)
		}
	}
}
