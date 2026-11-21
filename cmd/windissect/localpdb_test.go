package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestPDB writes the smallest MSF 7.00 file pdbIdentityKey can read:
// a PDB information stream (1) with infoAge and guid, and a DBI stream (3)
// with dbiAge. Layout, 512-byte blocks: 0 superblock, 1-2 free block maps,
// 3 block map, 4 stream directory, 5 stream 1, 6 stream 3.
func writeTestPDB(t *testing.T, path string, guid [16]byte, infoAge, dbiAge uint32) {
	t.Helper()
	const bs = 512
	file := make([]byte, 7*bs)
	le := binary.LittleEndian
	copy(file, pdbMagic)
	le.PutUint32(file[32:], bs)
	le.PutUint32(file[36:], 1)
	le.PutUint32(file[40:], 7)
	dir := []uint32{4, 0, 28, 0, 12, 5, 6} // count, sizes, stream 1 block, stream 3 block
	le.PutUint32(file[44:], uint32(len(dir)*4))
	le.PutUint32(file[52:], 3)
	le.PutUint32(file[3*bs:], 4)
	for i, v := range dir {
		le.PutUint32(file[4*bs+i*4:], v)
	}
	info := file[5*bs:]
	le.PutUint32(info[0:], 20000404)
	le.PutUint32(info[8:], infoAge)
	copy(info[12:28], guid[:])
	le.PutUint32(file[6*bs+8:], dbiAge)
	if err := os.WriteFile(path, file, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The GUID's first three fields are stored little-endian, as in the PE's
// CodeView record; the key prints them as numbers.
var testGUID = [16]byte{
	0x51, 0x39, 0xF6, 0x01, 0xDF, 0xF6, 0x95, 0x0E,
	0xDC, 0xD6, 0x50, 0x58, 0x92, 0x20, 0xB4, 0xFC,
}

const testKey = "01F63951F6DF0E95DCD650589220B4FC1"

func TestPDBIdentityKeyUsesDBIAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pdb")
	writeTestPDB(t, path, testGUID, 3, 1)
	got, err := pdbIdentityKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != testKey {
		t.Fatalf("key = %s, want %s", got, testKey)
	}
}

func TestPDBIdentityKeyRejectsNonPDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.pdb")
	if err := os.WriteFile(path, []byte("not a pdb at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pdbIdentityKey(path); err == nil {
		t.Fatal("a non-PDB file was accepted")
	}
}

func TestFindLocalPDBNextToBinary(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "cfgbkend.dll")
	if err := os.WriteFile(binary, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Spelled differently from the name the binary records, as on a
	// case-sensitive disk after a copy from Windows.
	writeTestPDB(t, filepath.Join(dir, "CfgBkend.pdb"), testGUID, 1, 1)

	if got := findLocalPDB(binary, "cfgbkend.pdb", testKey); !strings.EqualFold(filepath.Base(got), "cfgbkend.pdb") {
		t.Fatalf("matching PDB not found, got %q", got)
	}
	if got := findLocalPDB(binary, "cfgbkend.pdb", "01F63951F6DF0E95DCD650589220B4FC2"); got != "" {
		t.Fatalf("a PDB for another build was used: %q", got)
	}
	if got := findLocalPDB(binary, "other.pdb", testKey); got != "" {
		t.Fatalf("found a PDB that does not exist: %q", got)
	}
}
