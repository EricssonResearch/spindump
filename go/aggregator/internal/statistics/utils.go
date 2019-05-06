package statistics

func Ewma(a uint, s uint) uint {
	if a == 0 {
		return s
	}
	return s >> 4 + (a*15) >> 4
}
