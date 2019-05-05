package aggregate

// representation of spindump json event
type Event struct {
  Type                string
  Event               string
  Addrs               []string
  Session             string
  Ts                  string
  Who                 string
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
