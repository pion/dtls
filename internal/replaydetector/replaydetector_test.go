package replaydetector

import (
	"reflect"
	"testing"
)

func TestReplayDetector(t *testing.T) {
	const largeSeq = 0x100000000000
	cases := map[string]struct {
		windowSize uint
		maxSeq     uint64
		input      []uint64
		valid      []bool
		expected   []uint64
	}{
		"Continuous": {16, 0x0000FFFFFFFFFFFF,
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
				true, true, true, true, true, true, true, true, true, true,
				true,
			},
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		},
		"ValidLargeJump": {16, 0x0000FFFFFFFFFFFF,
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, largeSeq, 11, largeSeq + 1, largeSeq + 2, largeSeq + 3},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
				true, true, true, true, true,
			},
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, largeSeq, largeSeq + 1, largeSeq + 2, largeSeq + 3},
		},
		"InvalidLargeJump": {16, 0x0000FFFFFFFFFFFF,
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, largeSeq, 11, 12, 13, 14, 15},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
				false, true, true, true, true, true,
			},
			[]uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15},
		},
		"DuplicateAfterValidJump": {196, 0x0000FFFFFFFFFFFF,
			[]uint64{0, 1, 2, 129, 0, 1, 2},
			[]bool{
				true, true, true, true, true, true, true,
			},
			[]uint64{0, 1, 2, 129},
		},
		"DuplicateAfterInvalidJump": {196, 0x0000FFFFFFFFFFFF,
			[]uint64{0, 1, 2, 128, 0, 1, 2},
			[]bool{
				true, true, true, false, true, true, true,
			},
			[]uint64{0, 1, 2},
		},
		"ContinuousOffset": {16, 0x0000FFFFFFFFFFFF,
			[]uint64{100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
				true, true, true, true, true,
			},
			[]uint64{100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114},
		},
		"Reordered": {128, 0x0000FFFFFFFFFFFF,
			[]uint64{96, 64, 16, 80, 32, 48, 8, 24, 88, 40, 128, 56, 72, 112, 104, 120},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
				true, true, true, true, true, true,
			},
			[]uint64{96, 64, 16, 80, 32, 48, 8, 24, 88, 40, 128, 56, 72, 112, 104, 120},
		},
		"Old": {100, 0x0000FFFFFFFFFFFF,
			[]uint64{24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 8, 16},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
				true, true, true, true, true, true,
			},
			[]uint64{24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128},
		},
		"ReplayedLater": {128, 0x0000FFFFFFFFFFFF,
			[]uint64{16, 32, 48, 64, 80, 96, 112, 128, 16, 32, 48, 64, 80, 96, 112, 128},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
				true, true, true, true, true, true,
			},
			[]uint64{16, 32, 48, 64, 80, 96, 112, 128},
		},
		"ReplayedQuick": {128, 0x0000FFFFFFFFFFFF,
			[]uint64{16, 16, 32, 32, 48, 48, 64, 64, 80, 80, 96, 96, 112, 112, 128, 128},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
				true, true, true, true, true, true,
			},
			[]uint64{16, 32, 48, 64, 80, 96, 112, 128},
		},
		"Strict": {0, 0x0000FFFFFFFFFFFF,
			[]uint64{1, 3, 2, 4, 5, 6, 7, 8, 9, 10},
			[]bool{
				true, true, true, true, true, true, true, true, true, true,
			},
			[]uint64{1, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		"Overflow": {128, 0x0000FFFFFFFFFFFF,
			[]uint64{0x0000FFFFFFFFFFFE, 0x0000FFFFFFFFFFFF, 0x0001000000000000, 0x0001000000000001},
			[]bool{
				true, true, true, true,
			},
			[]uint64{0x0000FFFFFFFFFFFE, 0x0000FFFFFFFFFFFF},
		},
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			det := New(c.windowSize, c.maxSeq)
			var out []uint64
			for i, seq := range c.input {
				accept, ok := det.Check(seq)
				if ok {
					if c.valid[i] {
						out = append(out, seq)
						accept()
					}
				}
			}
			if !reflect.DeepEqual(c.expected, out) {
				t.Errorf("Wrong replay detection result:\nexpected: %v\ngot:      %v",
					c.expected, out,
				)
			}
		})
	}
}
