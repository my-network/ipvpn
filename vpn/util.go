package vpn

func max(a ...uint) uint {
	if len(a) == 0 {
		return 0
	}
	r := a[0]
	if len(a) > 1 {
		for _, v := range a[1:] {
			if v > r {
				r = v
			}
		}
	}
	return r
}
