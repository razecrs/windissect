package main

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func TestAnalyzePEKeepsFactsSeparateFromHeuristics(t *testing.T) {
	data := minimalPE64()
	report, err := analyzePE("probe.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != "PE32+" || report.Architecture != "x86-64" || report.EntryPoint != "0x1000" {
		t.Fatalf("unexpected identity: %#v", report)
	}
	if report.SHA256 == "" || len(report.Sections) != 1 || report.Sections[0].Name != ".text" {
		t.Fatalf("missing evidence: %#v", report)
	}
	if report.Signature.Present || report.Signature.Verified {
		t.Fatalf("unsigned fixture reported signed: %#v", report.Signature)
	}
	if !strings.Contains(strings.Join(report.Notes, " "), "not intent") {
		t.Fatalf("report lost its evidence caveat: %#v", report.Notes)
	}
}

func TestFindCodeViewRSDS(t *testing.T) {
	record := append([]byte("RSDS"), make([]byte, 16)...)
	age := make([]byte, 4)
	binary.LittleEndian.PutUint32(age, 7)
	record = append(record, age...)
	record = append(record, []byte(`C:\symbols\probe.pdb`)...)
	record = append(record, 0)
	debug := findCodeView(record)
	if debug == nil || debug.PDBAge != 7 || debug.PDBPath != `C:\symbols\probe.pdb` {
		t.Fatalf("unexpected CodeView record: %#v", debug)
	}
}

func TestAnalyzeLocalWindissect(t *testing.T) {
	if os.Getenv("WINDISSECT_LIVE_TESTS") != "1" {
		t.Skip("set WINDISSECT_LIVE_TESTS=1 to inspect the local release binary")
	}
	data, err := os.ReadFile(`..\windissect.exe`)
	if err != nil {
		t.Fatal(err)
	}
	report, err := analyzePE("windissect.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	if report.Format == "" || report.Architecture == "" || len(report.Sections) == 0 || report.SHA256 == "" {
		t.Fatalf("incomplete real-binary report: %#v", report)
	}
}

func minimalPE64() []byte {
	data := make([]byte, 0x400)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	coff := data[0x84:]
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)
	binary.LittleEndian.PutUint16(coff[2:], 1)
	binary.LittleEndian.PutUint32(coff[4:], 1_700_000_000)
	binary.LittleEndian.PutUint16(coff[16:], 0xf0)
	binary.LittleEndian.PutUint16(coff[18:], 0x22)
	optional := data[0x98:]
	binary.LittleEndian.PutUint16(optional[0:], 0x20b)
	binary.LittleEndian.PutUint32(optional[16:], 0x1000)
	binary.LittleEndian.PutUint32(optional[20:], 0x1000)
	binary.LittleEndian.PutUint64(optional[24:], 0x140000000)
	binary.LittleEndian.PutUint32(optional[32:], 0x1000)
	binary.LittleEndian.PutUint32(optional[36:], 0x200)
	binary.LittleEndian.PutUint32(optional[56:], 0x2000)
	binary.LittleEndian.PutUint32(optional[60:], 0x200)
	binary.LittleEndian.PutUint16(optional[68:], 3)
	binary.LittleEndian.PutUint16(optional[70:], 0x8160)
	binary.LittleEndian.PutUint64(optional[72:], 0x100000)
	binary.LittleEndian.PutUint64(optional[80:], 0x1000)
	binary.LittleEndian.PutUint64(optional[88:], 0x100000)
	binary.LittleEndian.PutUint64(optional[96:], 0x1000)
	binary.LittleEndian.PutUint32(optional[108:], 16)
	section := data[0x188:]
	copy(section[0:], ".text")
	binary.LittleEndian.PutUint32(section[8:], 8)
	binary.LittleEndian.PutUint32(section[12:], 0x1000)
	binary.LittleEndian.PutUint32(section[16:], 0x200)
	binary.LittleEndian.PutUint32(section[20:], 0x200)
	binary.LittleEndian.PutUint32(section[36:], 0x60000020)
	copy(data[0x200:], []byte{0x48, 0x31, 0xc0, 0xc3})
	return data
}
