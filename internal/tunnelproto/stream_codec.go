package tunnelproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const (
	streamRecordVersion   = 2
	streamRecordVersionV2 = 3
	streamRecordHeader    = 6
)

const (
	streamRecordFrame byte = 1
)

// ReadStreamMessage reads a tunnel message framed over an opaque byte stream.
func ReadStreamMessage(r io.Reader, maxPayloadBytes int64, dst *Message) error {
	return readStreamMessageVersion(r, maxPayloadBytes, dst, streamRecordVersion)
}

func ReadStreamMessageV2(r io.Reader, maxPayloadBytes int64, dst *Message) error {
	return readStreamMessageVersion(r, maxPayloadBytes, dst, streamRecordVersionV2)
}

func readStreamMessageVersion(r io.Reader, maxPayloadBytes int64, dst *Message, recordVersion byte) error {
	var header [streamRecordHeader]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if header[0] != recordVersion {
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

	id, meta, payload, err := readStreamFrameSections(r, idLen, metaLen, bodyLen)
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
	return writeStreamJSONVersion(w, msg, streamRecordVersion)
}

func WriteStreamJSONV2(w io.Writer, msg Message) error {
	return writeStreamJSONVersion(w, msg, streamRecordVersionV2)
}

func writeStreamJSONVersion(w io.Writer, msg Message, recordVersion byte) error {
	enc, err := encodeMessageFrame(msg)
	if err != nil {
		return err
	}
	return writeStreamRecord(w, enc, recordVersion)
}

// WriteStreamBinaryFrame writes a binary tunnel frame to an opaque byte stream.
func WriteStreamBinaryFrame(w io.Writer, frameKind byte, id string, wsMessageType int, payload []byte) error {
	return writeStreamBinaryFrameVersion(w, frameKind, id, wsMessageType, payload, streamRecordVersion)
}

func WriteStreamBinaryFrameV2(w io.Writer, frameKind byte, id string, wsMessageType int, payload []byte) error {
	return writeStreamBinaryFrameVersion(w, frameKind, id, wsMessageType, payload, streamRecordVersionV2)
}

func writeStreamBinaryFrameVersion(w io.Writer, frameKind byte, id string, wsMessageType int, payload []byte, recordVersion byte) error {
	if recordVersion == streamRecordVersionV2 {
		enc, err := newEncodedFrame(streamFrameKind(frameKind), id, wsMessageType, nil, payload)
		if err != nil {
			return err
		}
		return writeStreamRecord(w, enc, recordVersion)
	}
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

func writeStreamRecord(w io.Writer, enc encodedFrame, recordVersion byte) error {
	var header [streamRecordHeader]byte
	header[0] = recordVersion
	header[1] = streamRecordFrame
	binary.BigEndian.PutUint32(header[2:6], uint32(encodedFrameLen(enc)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	return writeEncodedFrame(w, enc)
}

func streamFrameKind(frameKind byte) byte {
	switch frameKind {
	case BinaryFrameReqBody:
		return frameKindReqBody
	case BinaryFrameRespBody:
		return frameKindRespBody
	case BinaryFrameWSData:
		return frameKindWSData
	default:
		return frameKind
	}
}

func readStreamFrameSection(r io.Reader, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func readStreamFrameSections(r io.Reader, idLen, metaLen, bodyLen int) ([]byte, []byte, []byte, error) {
	total := idLen + metaLen + bodyLen
	if total <= 0 {
		return nil, nil, nil, nil
	}
	buf, err := readStreamFrameSection(r, total)
	if err != nil {
		return nil, nil, nil, err
	}
	offset := 0
	var id, meta, payload []byte
	if idLen > 0 {
		id = buf[:idLen]
		offset = idLen
	}
	if metaLen > 0 {
		meta = buf[offset : offset+metaLen]
		offset += metaLen
	}
	if bodyLen > 0 {
		payload = buf[offset : offset+bodyLen]
	}
	return id, meta, payload, nil
}
