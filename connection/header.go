package connection

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

var (
	// internal special headers
	RequestUserHeaders  = "cf-cloudflared-request-headers"
	ResponseUserHeaders = "cf-cloudflared-response-headers"
	ResponseMetaHeader  = "cf-cloudflared-response-meta"

	// internal special headers
	CanonicalResponseUserHeaders = http.CanonicalHeaderKey(ResponseUserHeaders)
	CanonicalResponseMetaHeader  = http.CanonicalHeaderKey(ResponseMetaHeader)
)

var (
	// pre-generate possible values for res. These are lazily initialized so
	// that a json.Marshal failure (unlikely for a small struct) does not
	// crash the process at package init time.
	metaHeaderOnce                    sync.Once
	responseMetaHeaderCfd             string
	responseMetaHeaderCfdFlowRateLimited string
	responseMetaHeaderOrigin          string
	metaHeaderInitErr                 error
)

// HTTPHeader is a custom header struct that expects only ever one value for the header.
// This structure is used to serialize the headers and attach them to the HTTP2 request when proxying.
type HTTPHeader struct {
	Name  string
	Value string
}

type responseMetaHeader struct {
	Source          string `json:"src"`
	FlowRateLimited bool   `json:"flow_rate_limited,omitempty"`
}

// initResponseMetaHeader serializes the response meta header. Unlike the
// original mustInitRespMetaHeader, this returns an error instead of panicking
// so that a marshal failure does not bring down the entire process.
func initResponseMetaHeader(src string, flowRateLimited bool) (string, error) {
	header, err := json.Marshal(responseMetaHeader{Source: src, FlowRateLimited: flowRateLimited})
	if err != nil {
		return "", errors.Wrapf(err, "Failed to serialize response meta header = %s", src)
	}
	return string(header), nil
}

// initMetaHeaders populates the package-level response header constants. It
// is safe to call concurrently; the first call wins, subsequent calls return
// the same cached values.
func initMetaHeaders() error {
	metaHeaderOnce.Do(func() {
		if cfd, err := initResponseMetaHeader("cloudflared", false); err != nil {
			metaHeaderInitErr = err
		} else {
			responseMetaHeaderCfd = cfd
		}
		if metaHeaderInitErr != nil {
			return
		}
		if cfdFlow, err := initResponseMetaHeader("cloudflared", true); err != nil {
			metaHeaderInitErr = err
		} else {
			responseMetaHeaderCfdFlowRateLimited = cfdFlow
		}
		if metaHeaderInitErr != nil {
			return
		}
		if origin, err := initResponseMetaHeader("origin", false); err != nil {
			metaHeaderInitErr = err
		} else {
			responseMetaHeaderOrigin = origin
		}
	})
	return metaHeaderInitErr
}

// responseMetaHeaderFor returns the cached response meta header constant for
// the given (source, flowRateLimited) combination. Callers should call
// initMetaHeaders() at least once (from main / server startup) before using
// these constants to ensure they are initialized.
func responseMetaHeaderFor(source string, flowRateLimited bool) string {
	if err := initMetaHeaders(); err != nil {
		// On the very unlikely chance init failed (impossible for the hard-coded
		// responseMetaHeader struct), fall back to a minimal JSON value so the
		// caller does not see an empty string header.
		return fmt.Sprintf(`{"src":"%s","flow_rate_limited":%t}`, source, flowRateLimited)
	}
	switch {
	case source == "cloudflared" && !flowRateLimited:
		return responseMetaHeaderCfd
	case source == "cloudflared" && flowRateLimited:
		return responseMetaHeaderCfdFlowRateLimited
	case source == "origin":
		return responseMetaHeaderOrigin
	default:
		return responseMetaHeaderCfd
	}
}

var headerEncoding = base64.RawStdEncoding

// IsControlResponseHeader is called in the direction of eyeball <- origin.
func IsControlResponseHeader(headerName string) bool {
	return strings.HasPrefix(headerName, ":") ||
		strings.HasPrefix(headerName, "cf-int-") ||
		strings.HasPrefix(headerName, "cf-cloudflared-") ||
		strings.HasPrefix(headerName, "cf-proxy-")
}

// isWebsocketClientHeader returns true if the header name is required by the client to upgrade properly
func IsWebsocketClientHeader(headerName string) bool {
	return headerName == "sec-websocket-accept" ||
		headerName == "connection" ||
		headerName == "upgrade"
}

// Serialize HTTP1.x headers by base64-encoding each header name and value,
// and then joining them in the format of [key:value;]
func SerializeHeaders(h1Headers http.Header) string {
	// compute size of the fully serialized value and largest temp buffer we will need
	serializedLen := 0
	maxTempLen := 0
	for headerName, headerValues := range h1Headers {
		for _, headerValue := range headerValues {
			nameLen := headerEncoding.EncodedLen(len(headerName))
			valueLen := headerEncoding.EncodedLen(len(headerValue))
			const delims = 2
			serializedLen += delims + nameLen + valueLen
			if nameLen > maxTempLen {
				maxTempLen = nameLen
			}
			if valueLen > maxTempLen {
				maxTempLen = valueLen
			}
		}
	}
	var buf strings.Builder
	buf.Grow(serializedLen)

	temp := make([]byte, maxTempLen)
	writeB64 := func(s string) {
		n := headerEncoding.EncodedLen(len(s))
		if n > len(temp) {
			temp = make([]byte, n)
		}
		headerEncoding.Encode(temp[:n], []byte(s))
		buf.Write(temp[:n])
	}

	for headerName, headerValues := range h1Headers {
		for _, headerValue := range headerValues {
			if buf.Len() > 0 {
				buf.WriteByte(';')
			}
			writeB64(headerName)
			buf.WriteByte(':')
			writeB64(headerValue)
		}
	}

	return buf.String()
}

// Deserialize headers serialized by `SerializeHeader`
func DeserializeHeaders(serializedHeaders string) ([]HTTPHeader, error) {
	const unableToDeserializeErr = "Unable to deserialize headers"

	deserialized := make([]HTTPHeader, 0)
	for _, serializedPair := range strings.Split(serializedHeaders, ";") {
		if len(serializedPair) == 0 {
			continue
		}

		serializedHeaderParts := strings.Split(serializedPair, ":")
		if len(serializedHeaderParts) != 2 {
			return nil, errors.New(unableToDeserializeErr)
		}

		serializedName := serializedHeaderParts[0]
		serializedValue := serializedHeaderParts[1]
		deserializedName := make([]byte, headerEncoding.DecodedLen(len(serializedName)))
		deserializedValue := make([]byte, headerEncoding.DecodedLen(len(serializedValue)))

		if _, err := headerEncoding.Decode(deserializedName, []byte(serializedName)); err != nil {
			return nil, errors.Wrap(err, unableToDeserializeErr)
		}
		if _, err := headerEncoding.Decode(deserializedValue, []byte(serializedValue)); err != nil {
			return nil, errors.Wrap(err, unableToDeserializeErr)
		}

		deserialized = append(deserialized, HTTPHeader{
			Name:  string(deserializedName),
			Value: string(deserializedValue),
		})
	}

	return deserialized, nil
}
