package tunnelproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const (
	streamRecordVersion = 2
	streamRecordHeader  = 6
)

const (
	streamRecordFrame byte = 1
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
	payloadLen := int64(binary.BigEndian.Uint32(header[2:6]))
	if maxPayloadBytes > 0 && payloadLen > maxPayloadBytes {
		return fmt.Errorf("stream payload exceeds read limit: %d > %d", payloadLen, maxPayloadBytes)
	}
	if payloadLen < binaryFrameHeader {
		return fmt.Errorf("stream payload shorter than frame header: %d", payloadLen)
	}
	if payloadLen > int64(math.MaxInt) {
		return fmt.Errorf("stream payload exceeds int limit: %d > %d", payloadLen, math.MaxInt)
	}
	if header[1] != streamRecordFrame {
		return fmt.Errorf("unsupported stream record type: %d", header[1])
	}

	var frameHeader [binaryFrameHeader]byte
	if _, err := io.ReadFull(r, frameHeader[:]); err != nil {
		return err
	}
	if frameHeader[0] != binaryFrameVersion {
		return fmt.Errorf("unsupported binary frame version: %d", frameHeader[0])
	}

	idLen := int(binary.BigEndian.Uint16(frameHeader[4:6]))
	metaLen := int(binary.BigEndian.Uint32(frameHeader[6:10]))
	bodyLen := int(binary.BigEndian.Uint32(frameHeader[10:14]))
	total := int64(binaryFrameHeader + idLen + metaLen + bodyLen)
	if total != payloadLen {
		return fmt.Errorf("stream payload/frame length mismatch: stream=%d frame=%d", payloadLen, total)
	}

	id, err := readStreamFrameSection(r, idLen)
	if err != nil {
		return err
	}
	meta, err := readStreamFrameSection(r, metaLen)
	if err != nil {
		return err
	}
	payload, err := readStreamFrameSection(r, bodyLen)
	if err != nil {
		return err
	}

	msg, err := decodeFrameParts(frameHeader[1], string(id), int(frameHeader[2]), meta, payload)
	if err != nil {
		return err
	}
	*dst = msg
	return nil
}

// WriteStreamJSON writes a JSON control message to an opaque byte stream.
func WriteStreamJSON(w io.Writer, msg Message) error {
	enc, err := encodeMessageFrame(msg)
	if err != nil {
		return err
	}
	return writeStreamRecord(w, enc)
}

// WriteStreamBinaryFrame writes a binary tunnel frame to an opaque byte stream.
func WriteStreamBinaryFrame(w io.Writer, frameKind byte, id string, wsMessageType int, payload []byte) error {
	switch frameKind {
	case BinaryFrameReqBody:
		return WriteStreamJSON(w, Message{
			Kind:      KindReqBody,
			BodyChunk: &BodyChunk{ID: id, Data: payload},
		})
	case BinaryFrameRespBody:
		return WriteStreamJSON(w, Message{
			Kind:      KindRespBody,
			BodyChunk: &BodyChunk{ID: id, Data: payload},
		})
	case BinaryFrameWSData:
		return WriteStreamJSON(w, Message{
			Kind: KindWSData,
			WSData: &WSData{
				ID:          id,
				MessageType: wsMessageType,
				Data:        payload,
			},
		})
	default:
		return fmt.Errorf("unsupported binary frame kind: %d", frameKind)
	}
}

func writeStreamRecord(w io.Writer, enc encodedFrame) error {
	var header [streamRecordHeader]byte
	header[0] = streamRecordVersion
	header[1] = streamRecordFrame
	binary.BigEndian.PutUint32(header[2:6], uint32(encodedFrameLen(enc)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	return writeEncodedFrame(w, enc)
}

func readStreamFrameSection(r io.Reader, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}
