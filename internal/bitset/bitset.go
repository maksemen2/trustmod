package bitset

import "math/bits"

type Bits []uint64

func New(size int) Bits {
	if size <= 0 {
		return nil
	}
	return make(Bits, (size+63)/64)
}

func (b Bits) Set(bit int) {
	b[bit/64] |= 1 << uint(bit%64)
}

func (b Bits) Clear(bit int) {
	b[bit/64] &^= 1 << uint(bit%64)
}

func (b Bits) Merge(other Bits) {
	for i := range other {
		b[i] |= other[i]
	}
}

func (b Bits) Count() int {
	total := 0
	for _, word := range b {
		total += bits.OnesCount64(word)
	}
	return total
}
