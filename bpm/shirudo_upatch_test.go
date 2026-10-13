package main

import (
	"encoding/binary"
	"testing"
)

func testShirudoUpatchBytes(t *testing.T, name string, flags uint32, source bool) []byte {
	t.Helper()

	body := make([]byte, shirudoUpatchHeaderSize)
	binary.LittleEndian.PutUint64(body[0:8], shirudoUpatchMagic)
	binary.LittleEndian.PutUint32(body[8:12], shirudoUpatchVersion)
	binary.LittleEndian.PutUint32(body[12:16], flags)
	binary.LittleEndian.PutUint32(body[352:356], shirudoUpatchTypeBPF)
	copy(body[16:16+shirudoUpatchNameMax], name)
	for i := 0; i < 32; i++ {
		body[272+i] = byte(i)
	}

	loaderOff := uint32(len(body))
	body = append(body, []byte{0xaa, 0xbb, 0xcc, 0xdd}...)
	signatureOff := uint32(len(body))
	body = append(body, []byte{0x01, 0x02, 0x03}...)
	dataOff := uint32(len(body))
	body = append(body, []byte{0x04, 0x05}...)

	var extraOff uint32
	if source {
		sourceName := []byte("examples/block-afalg.bpf.c")
		sourceText := []byte("SEC(\"lsm/socket_create\") int BPF_PROG(block_afalg) { return 0; }\n")
		extraOff = uint32(len(body))
		extra := make([]byte, 16)
		binary.LittleEndian.PutUint32(extra[0:4], 0x52545853)
		binary.LittleEndian.PutUint32(extra[4:8], 1)
		binary.LittleEndian.PutUint32(extra[8:12], uint32(len(sourceName)))
		binary.LittleEndian.PutUint32(extra[12:16], uint32(len(sourceText)))
		body = append(body, extra...)
		body = append(body, sourceName...)
		body = append(body, sourceText...)
	}

	binary.LittleEndian.PutUint32(body[304:308], loaderOff)
	binary.LittleEndian.PutUint32(body[308:312], 4)
	binary.LittleEndian.PutUint32(body[312:316], signatureOff)
	binary.LittleEndian.PutUint32(body[316:320], 3)
	binary.LittleEndian.PutUint32(body[328:332], dataOff)
	binary.LittleEndian.PutUint32(body[332:336], 2)
	binary.LittleEndian.PutUint32(body[336:340], 1024)
	binary.LittleEndian.PutUint32(body[340:344], 1)
	binary.LittleEndian.PutUint32(body[344:348], 1)
	binary.LittleEndian.PutUint32(body[348:352], extraOff)

	return body
}
