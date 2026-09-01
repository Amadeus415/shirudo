package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	shirudoUpatchMagic      = 0x53485244554e4150
	shirudoUpatchVersion    = 1
	shirudoDirectiveUnload  = 1 << 0
	shirudoUpatchNameMax    = 256
	shirudoUpatchLegacySize = 352
	shirudoUpatchHeaderSize = 360
	shirudoUpatchTypeBPF    = 1
	shirudoUpatchTypeJava   = 2
)

type shirudoUpatchHeader struct {
	Name            string
	Directive       string
	Version         uint32
	PayloadType     string
	PayloadSHA256   string
	LoaderInsnsOff  uint32
	LoaderInsnsLen  uint32
	SignatureOff    uint32
	SignatureLen    uint32
	MetadataOff     uint32
	MetadataLen     uint32
	DataOff         uint32
	DataLen         uint32
	LogBufSize      uint32
	NrMaps          uint32
	NrProgs         uint32
	ExtraOff        uint32
	HasSourceExtras bool
	SourceFile      string
}

func parseShirudoUpatch(body []byte) (shirudoUpatchHeader, error) {
	if len(body) < shirudoUpatchLegacySize {
		return shirudoUpatchHeader{}, fmt.Errorf("file is shorter than Shirudo upatch header")
	}

	magic := binary.LittleEndian.Uint64(body[0:8])
	if magic != shirudoUpatchMagic {
		return shirudoUpatchHeader{}, fmt.Errorf("bad magic 0x%x", magic)
	}

	version := binary.LittleEndian.Uint32(body[8:12])
	if version != shirudoUpatchVersion {
		return shirudoUpatchHeader{}, fmt.Errorf("unsupported upatch version %d", version)
	}

	flags := binary.LittleEndian.Uint32(body[12:16])
	if flags&^uint32(shirudoDirectiveUnload) != 0 {
		return shirudoUpatchHeader{}, fmt.Errorf("unsupported upatch flags 0x%x", flags)
	}

	h := shirudoUpatchHeader{
		Name:           cString(body[16 : 16+shirudoUpatchNameMax]),
		Directive:      "load",
		Version:        version,
		PayloadSHA256:  hex.EncodeToString(body[272:304]),
		LoaderInsnsOff: binary.LittleEndian.Uint32(body[304:308]),
		LoaderInsnsLen: binary.LittleEndian.Uint32(body[308:312]),
		SignatureOff:   binary.LittleEndian.Uint32(body[312:316]),
		SignatureLen:   binary.LittleEndian.Uint32(body[316:320]),
		MetadataOff:    binary.LittleEndian.Uint32(body[320:324]),
		MetadataLen:    binary.LittleEndian.Uint32(body[324:328]),
		DataOff:        binary.LittleEndian.Uint32(body[328:332]),
		DataLen:        binary.LittleEndian.Uint32(body[332:336]),
		LogBufSize:     binary.LittleEndian.Uint32(body[336:340]),
		NrMaps:         binary.LittleEndian.Uint32(body[340:344]),
		NrProgs:        binary.LittleEndian.Uint32(body[344:348]),
		ExtraOff:       binary.LittleEndian.Uint32(body[348:352]),
		PayloadType:    "bpf",
	}
	headerSize := shirudoUpatchLegacySize
	if len(body) >= shirudoUpatchHeaderSize {
		typeValue := binary.LittleEndian.Uint32(body[352:356])
		reserved := binary.LittleEndian.Uint32(body[356:360])
		if reserved == 0 && (typeValue == shirudoUpatchTypeJava ||
			h.LoaderInsnsOff >= shirudoUpatchHeaderSize) {
			headerSize = shirudoUpatchHeaderSize
			switch typeValue {
			case shirudoUpatchTypeBPF:
				h.PayloadType = "bpf"
			case shirudoUpatchTypeJava:
				h.PayloadType = "java"
			default:
				return shirudoUpatchHeader{}, fmt.Errorf("unsupported upatch type %d", typeValue)
			}
		}
	}
	if flags&uint32(shirudoDirectiveUnload) != 0 {
		h.Directive = "unload"
	}

	if h.PayloadType == "java" {
		if h.LoaderInsnsLen != 0 || h.SignatureLen != 0 {
			return shirudoUpatchHeader{}, fmt.Errorf("invalid Java upatch sections")
		}
		if h.Directive == "unload" {
			if h.DataLen != 0 || h.MetadataLen != 32 {
				return shirudoUpatchHeader{}, fmt.Errorf("invalid Java unload sections")
			}
		} else if h.DataLen == 0 {
			return shirudoUpatchHeader{}, fmt.Errorf("Java payload is empty")
		}
	}
	if h.PayloadType == "bpf" && (h.LoaderInsnsLen == 0 || h.SignatureLen == 0) {
		return shirudoUpatchHeader{}, fmt.Errorf("BPF loader and signature sections are required")
	}
	if err := validateUpatchSection("loader_insns", h.LoaderInsnsOff, h.LoaderInsnsLen, len(body), headerSize, h.PayloadType == "bpf"); err != nil {
		return shirudoUpatchHeader{}, err
	}
	if err := validateUpatchSection("signature", h.SignatureOff, h.SignatureLen, len(body), headerSize, h.PayloadType == "bpf"); err != nil {
		return shirudoUpatchHeader{}, err
	}
	if err := validateUpatchSection("metadata", h.MetadataOff, h.MetadataLen, len(body), headerSize, false); err != nil {
		return shirudoUpatchHeader{}, err
	}
	if err := validateUpatchSection("data", h.DataOff, h.DataLen, len(body), headerSize, h.PayloadType == "java" && h.Directive != "unload"); err != nil {
		return shirudoUpatchHeader{}, err
	}

	h.HasSourceExtras, h.SourceFile = parseUpatchSourceExtras(body, h.ExtraOff)
	return h, nil
}

func validateUpatchSection(name string, off uint32, length uint32, fileSize int, headerSize int, required bool) error {
	if length == 0 {
		if required {
			return fmt.Errorf("%s section is empty", name)
		}
		return nil
	}
	if off < uint32(headerSize) {
		return fmt.Errorf("%s section starts inside header", name)
	}
	if uint64(off)+uint64(length) > uint64(fileSize) {
		return fmt.Errorf("%s section exceeds file size", name)
	}
	return nil
}

func parseUpatchSourceExtras(body []byte, off uint32) (bool, string) {
	if off == 0 || off < shirudoUpatchLegacySize || uint64(off)+16 > uint64(len(body)) {
		return false, ""
	}

	start := int(off)
	extras := body[start:]
	if binary.LittleEndian.Uint32(extras[0:4]) != 0x52545853 ||
		binary.LittleEndian.Uint32(extras[4:8]) != 1 {
		return false, ""
	}
	nameLen := binary.LittleEndian.Uint32(extras[8:12])
	sourceLen := binary.LittleEndian.Uint32(extras[12:16])
	if uint64(off)+16+uint64(nameLen)+uint64(sourceLen) > uint64(len(body)) {
		return false, ""
	}
	nameStart := start + 16
	nameEnd := nameStart + int(nameLen)
	return true, string(body[nameStart:nameEnd])
}

func cString(raw []byte) string {
	if n := bytes.IndexByte(raw, 0); n >= 0 {
		raw = raw[:n]
	}
	return strings.TrimSpace(string(raw))
}
