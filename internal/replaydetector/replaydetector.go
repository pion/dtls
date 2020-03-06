// Package replaydetector provides packet replay detection algorithm.
package replaydetector

// ReplayDetector is the interface of sequence replay detector.
type ReplayDetector interface {
	// Check returns true if given sequence number is not replayed.
	// Call accept() to mark the packet is received properly.
	Check(seq uint64) (accept func(), ok bool)
}

type slidingWindowDetector struct {
	latestSeq  uint64
	maxSeq     uint64
	windowSize uint
	mask       *fixedBigInt
}

// New creates ReplayDetector.
func New(windowSize uint, maxSeq uint64) ReplayDetector {
	return &slidingWindowDetector{
		maxSeq:     maxSeq,
		windowSize: windowSize,
		mask:       newFixedBigInt(windowSize),
	}
}

func (d *slidingWindowDetector) Check(seq uint64) (accept func(), ok bool) {
	if seq > d.maxSeq {
		// Exceeded upper limit.
		return func() {}, false
	}

	if seq <= d.latestSeq {
		if d.latestSeq > uint64(d.windowSize)+seq {
			return func() {}, false
		}
		if d.mask.Bit(uint(d.latestSeq-seq)) != 0 {
			// The sequence number is duplicated.
			return func() {}, false
		}
	}

	return func() {
		if seq > d.latestSeq {
			// Update the head of the window.
			d.mask.Lsh(uint(seq - d.latestSeq))
			d.latestSeq = seq
		}
		d.mask.SetBit(uint(d.latestSeq - seq))
	}, true
}
