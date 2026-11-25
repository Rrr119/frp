package tunnel

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"sync"
	"sync/atomic"

	"github.com/golang/snappy"
)

const (
	snappyMagicChunk = "\xff\x06\x00\x00sNaPpY"

	snappyChunkCompressed   = 0x00
	snappyChunkUncompressed = 0x01

	snappyMaxBlockSize = 65536
	snappyHeaderSize   = 4
	snappyCRCSize      = 4
	snappyFrameHeader  = snappyHeaderSize + snappyCRCSize
)

var snappyCRCTable = crc32.MakeTable(crc32.Castagnoli)

type adaptiveStats struct {
	payloadBytes    atomic.Uint64
	wireBytes       atomic.Uint64
	compressedBlock atomic.Uint64
	rawBlocks       atomic.Uint64
	skippedBlocks   atomic.Uint64
}

// Stats contains local observations used and exposed by the adaptive writer.
type Stats struct {
	PayloadBytes     uint64
	WireBytes        uint64
	CompressedBlocks uint64
	RawBlocks        uint64
	SkippedBlocks    uint64
}

var frameBufferPool = sync.Pool{
	New: func() any {
		size := len(snappyMagicChunk) + snappyFrameHeader + snappy.MaxEncodedLen(snappyMaxBlockSize)
		b := make([]byte, size)
		return &b
	},
}

// AdaptiveWriter writes standard Snappy frames, but avoids Snappy encoding for
// small or high-entropy blocks and applies network-profile-specific thresholds.
// Its output can be decoded by any Snappy framing reader, including older frp
// releases.
type AdaptiveWriter struct {
	w       io.Writer
	profile atomic.Value // NetworkProfile
	stats   adaptiveStats

	writeMu    sync.Mutex
	headerSent bool
	err        error
	header     [len(snappyMagicChunk) + snappyFrameHeader]byte
}

// NewAdaptiveWriter creates a network-aware Snappy framing writer.
func NewAdaptiveWriter(w io.Writer, profile NetworkProfile) *AdaptiveWriter {
	p, err := ParseNetworkProfile(string(profile))
	if err != nil {
		p = NetworkWAN
	}
	aw := &AdaptiveWriter{w: w}
	aw.profile.Store(p)
	return aw
}

// SetProfile changes the policy used by subsequent Write calls.
func (w *AdaptiveWriter) SetProfile(profile NetworkProfile) error {
	p, err := ParseNetworkProfile(string(profile))
	if err != nil {
		return err
	}
	w.profile.Store(p)
	return nil
}

// Profile returns the active canonical network profile.
func (w *AdaptiveWriter) Profile() NetworkProfile {
	p, _ := w.profile.Load().(NetworkProfile)
	if p == "" {
		return NetworkWAN
	}
	return p
}

// Stats returns a snapshot of writer decisions and byte counts.
func (w *AdaptiveWriter) Stats() Stats {
	return Stats{
		PayloadBytes:     w.stats.payloadBytes.Load(),
		WireBytes:        w.stats.wireBytes.Load(),
		CompressedBlocks: w.stats.compressedBlock.Load(),
		RawBlocks:        w.stats.rawBlocks.Load(),
		SkippedBlocks:    w.stats.skippedBlocks.Load(),
	}
}

// Write implements io.Writer. It is not safe for concurrent Write calls, as is
// usual for stream writers; profile updates may happen concurrently.
func (w *AdaptiveWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if w.err != nil {
		return 0, w.err
	}

	written := 0
	for len(p) > 0 {
		n := min(len(p), snappyMaxBlockSize)
		if err := w.writeBlock(p[:n]); err != nil {
			w.err = err
			return written, err
		}
		written += n
		w.stats.payloadBytes.Add(uint64(n))
		p = p[n:]
	}
	return written, nil
}

func (w *AdaptiveWriter) writeBlock(block []byte) error {
	policy := policyFor(w.Profile())
	compress := len(block) >= policy.minBytes && looksCompressible(block, policy)
	if !compress {
		w.stats.skippedBlocks.Add(1)
	}

	checksum := maskedCRC(block)
	if !compress {
		return w.writeRawBlock(block, checksum)
	}

	bufPtr := frameBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer frameBufferPool.Put(bufPtr)

	const (
		magicOffset  = 0
		headerOffset = len(snappyMagicChunk)
		bodyOffset   = headerOffset + snappyFrameHeader
	)

	chunkType := uint8(snappyChunkUncompressed)
	bodyLen := len(block)

	encoded := snappy.Encode(buf[bodyOffset:], block)
	savings := 1 - float64(len(encoded))/float64(len(block))
	if savings < policy.minWireSavings {
		return w.writeRawBlock(block, checksum)
	}

	chunkType = snappyChunkCompressed
	bodyLen = len(encoded)
	chunkLength := snappyCRCSize + bodyLen
	buf[headerOffset] = chunkType
	buf[headerOffset+1] = byte(chunkLength)
	buf[headerOffset+2] = byte(chunkLength >> 8)
	buf[headerOffset+3] = byte(chunkLength >> 16)
	binary.LittleEndian.PutUint32(buf[headerOffset+snappyHeaderSize:headerOffset+snappyFrameHeader], checksum)

	writeStart := headerOffset
	if !w.headerSent {
		copy(buf[magicOffset:headerOffset], snappyMagicChunk)
		writeStart = magicOffset
		w.headerSent = true
	}

	end := bodyOffset + bodyLen
	n, err := w.w.Write(buf[writeStart:end])
	w.stats.wireBytes.Add(uint64(n))
	if err == nil {
		w.stats.compressedBlock.Add(1)
	}
	return err
}

func (w *AdaptiveWriter) writeRawBlock(block []byte, checksum uint32) error {
	const headerOffset = len(snappyMagicChunk)
	prefix := w.header[:]

	writeHeader := prefix[headerOffset:]
	if !w.headerSent {
		copy(prefix[:headerOffset], snappyMagicChunk)
		writeHeader = prefix[:]
		w.headerSent = true
	}

	chunkLength := snappyCRCSize + len(block)
	frameHeader := prefix[headerOffset : headerOffset+snappyFrameHeader]
	frameHeader[0] = snappyChunkUncompressed
	frameHeader[1] = byte(chunkLength)
	frameHeader[2] = byte(chunkLength >> 8)
	frameHeader[3] = byte(chunkLength >> 16)
	binary.LittleEndian.PutUint32(frameHeader[snappyHeaderSize:], checksum)

	headerN, err := w.w.Write(writeHeader)
	w.stats.wireBytes.Add(uint64(headerN))
	if err != nil {
		return err
	}

	bodyN, err := w.w.Write(block)
	w.stats.wireBytes.Add(uint64(bodyN))
	if err == nil {
		w.stats.rawBlocks.Add(1)
	}
	return err
}

func looksCompressible(b []byte, policy compressionPolicy) bool {
	sample := b
	if len(sample) > policy.sampleBytes {
		sample = sample[:policy.sampleBytes]
	}
	if len(sample) == 0 {
		return false
	}

	var seen [256]bool
	distinct := 0
	for _, c := range sample {
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	return distinct <= policy.maxDistinct
}

func maskedCRC(b []byte) uint32 {
	c := crc32.Update(0, snappyCRCTable, b)
	return (c>>15 | c<<17) + 0xa282ead8
}
