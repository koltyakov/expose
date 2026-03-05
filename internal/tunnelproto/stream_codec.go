package tunnelproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	streamRecordVersion = 1
	streamRecordHeader  = 6
)

const (
	streamRecordJSON   byte = 1
	streamRecordBinary byte = 2
)

// ReadStreamMessage reads a tunnel message framed over an opaque byte stream.
func ReadStreamMessage(r io.Reader, maxPayloadBytes int64, dst *Message) error {
	var header [streamRecordHeader]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if header[0] != streamRecordVersion {
		return fmt.Errorf("unsupported stream record version: %d", header[0])
	}

	recordType := header[1]
	payloadLen := int64(binary.BigEndian.Uint32(header[2:6]))
	if payloadLen < 0 {
		return errors.New("invalid stream payload length")
	}
	if maxPayloadBytes > 0 && payloadLen > maxPayloadBytes {
		return fmt.Errorf("stream payload exceeds read limit: %d > %d", payloadLen, maxPayloadBytes)
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}

	switch recordType {
	case streamRecordJSON:
		var msg Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			return err
		}
		*dst = msg
		return nil
	case streamRecordBinary:
		msg, err := decodeBinaryFrame(payload)
		if err != nil {
			return err
		}
		*dst = msg
		return nil
	default:
		return fmt.Errorf("unsupported stream record type: %d", recordType)
	}
}

// WriteStreamJSON writes a JSON control message to an opaque byte stream.
func WriteStreamJSON(w io.Writer, msg Message) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return writeStreamRecord(w, streamRecordJSON, payload)
}

// WriteStreamBinaryFrame writes a binary tunnel frame to an opaque byte stream.
func WriteStreamBinaryFrame(w io.Writer, frameKind byte, id string, wsMessageType int, payload []byte) error {
	var buf bytes.Buffer
	if err := WriteBinaryFrame(&buf, frameKind, id, wsMessageType, payload); err != nil {
		return err
	}
	return writeStreamRecord(w, streamRecordBinary, buf.Bytes())
}

func writeStreamRecord(w io.Writer, recordType byte, payload []byte) error {
	var header [streamRecordHeader]byte
	header[0] = streamRecordVersion
	header[1] = recordType
	binary.BigEndian.PutUint32(header[2:6], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}
