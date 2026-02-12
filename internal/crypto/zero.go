package crypto

func (impl *Impl) Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
