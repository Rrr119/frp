package tunnel

import (
	"fmt"
	"io"

	libio "github.com/fatedier/golib/io"
	gopool "github.com/fatedier/golib/pool"
	"github.com/golang/snappy"
)

// CompressionOptions configures Snappy compression for a tunnel.
type CompressionOptions struct {
	Enabled bool
	// Adaptive uses network-aware standard Snappy frames instead of always
	// running Snappy block encoding. Both formats are decoded by snappy.Reader.
	Adaptive bool
	Network  NetworkProfile
}

// Options configures tunnel-level encryption and compression wrappers.
type Options struct {
	Encryption  bool
	Key         []byte
	Compression CompressionOptions
}

// Wrap applies encryption first and compression second, matching frp's
// historical byte order: application data is compressed, then encrypted.
func Wrap(rwc io.ReadWriteCloser, opts Options) (io.ReadWriteCloser, func(), error) {
	recycle := func() {}
	if opts.Encryption {
		wrapped, err := libio.WithEncryption(rwc, opts.Key)
		if err != nil {
			_ = rwc.Close()
			return nil, nil, fmt.Errorf("create encryption stream: %w", err)
		}
		rwc = wrapped
	}

	if opts.Compression.Enabled {
		rwc, recycle = WithCompressionFromPool(rwc, opts.Compression.Adaptive, opts.Compression.Network)
	}
	return rwc, recycle, nil
}

// WithCompressionFromPool wraps rwc with a pooled Snappy reader and either the
// legacy Snappy writer or the adaptive standard-frame writer.
func WithCompressionFromPool(rwc io.ReadWriteCloser, adaptive bool, network NetworkProfile) (io.ReadWriteCloser, func()) {
	reader := gopool.GetSnappyReader(rwc)

	var writer io.Writer
	recycleWriter := func() {}
	if adaptive {
		writer = NewAdaptiveWriter(rwc, network)
	} else {
		sw := gopool.GetSnappyWriter(rwc)
		writer = sw
		recycleWriter = func() {
			gopool.PutSnappyWriter(sw)
		}
	}

	wrapped := libio.WrapReadWriteCloser(reader, writer, func() error {
		return rwc.Close()
	})
	recycle := func() {
		gopool.PutSnappyReader(reader)
		recycleWriter()
	}
	return wrapped, recycle
}

// WithCompression wraps rwc without taking reusable Snappy codecs from pools.
func WithCompression(rwc io.ReadWriteCloser, adaptive bool, network NetworkProfile) io.ReadWriteCloser {
	reader := snappy.NewReader(rwc)
	var writer io.Writer
	if adaptive {
		writer = NewAdaptiveWriter(rwc, network)
	} else {
		writer = snappy.NewWriter(rwc)
	}
	return libio.WrapReadWriteCloser(reader, writer, func() error {
		if closer, ok := writer.(io.Closer); ok {
			_ = closer.Close()
		}
		return rwc.Close()
	})
}
