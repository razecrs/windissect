package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// findLocalPDB returns a PDB the user already has for this binary: one named
// pdbName next to the binary or in the working directory, and only if its
// identity matches key (the symbol-server GUID+age the binary expects). A
// stale PDB with the right name is skipped, so the pull falls back to the
// cache or the symbol server instead of extracting against the wrong build.
func findLocalPDB(binaryPath, pdbName, key string) string {
	dirs := []string{filepath.Dir(binaryPath)}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	seen := map[string]bool{}
	for _, dir := range dirs {
		abs, err := filepath.Abs(dir)
		if err != nil || seen[abs] {
			continue
		}
		seen[abs] = true
		candidate := findFileFold(abs, pdbName)
		if candidate == "" {
			continue
		}
		got, err := pdbIdentityKey(candidate)
		if err != nil {
			fmt.Printf("[!] Ignoring %s: %v\n", candidate, err)
			continue
		}
		if got != key {
			fmt.Printf("[!] Ignoring %s: it is for build %s, the binary expects %s\n", candidate, got, key)
			continue
		}
		return candidate
	}
	return ""
}

// pdbIdentityKey reads a PDB's symbol-server key (GUID followed by age in
// hex), the same key the binary's CodeView record produces. Like the
// extractor (src/pdbsym.rs), it takes the age from the DBI stream: the PDB
// information stream's age can differ, and Microsoft serves such PDBs under
// the DBI age.
func pdbIdentityKey(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	msf, err := openMSF(f)
	if err != nil {
		return "", err
	}
	info, err := msf.stream(1, 28)
	if err != nil {
		return "", fmt.Errorf("PDB information stream: %w", err)
	}
	if len(info) < 28 {
		return "", errors.New("PDB information stream is too short")
	}
	age := binary.LittleEndian.Uint32(info[8:12])
	if dbi, err := msf.stream(3, 12); err == nil && len(dbi) >= 12 {
		age = binary.LittleEndian.Uint32(dbi[8:12])
	}
	g := info[12:28]
	guid := fmt.Sprintf("%08X%04X%04X%X",
		binary.LittleEndian.Uint32(g[0:4]),
		binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		g[8:16])
	return symbolKey(guid, age), nil
}

// msfFile reads streams out of an MSF 7.00 container, the format PDBs use:
// a superblock, then a stream directory whose block list lives in a block
// map. Only the first bytes of a stream are ever needed here.
type msfFile struct {
	r          io.ReaderAt
	blockSize  uint32
	numBlocks  uint32
	sizes      []uint32
	blockLists [][]uint32
}

func openMSF(r io.ReaderAt) (*msfFile, error) {
	super := make([]byte, 56)
	if _, err := r.ReadAt(super, 0); err != nil {
		return nil, fmt.Errorf("read superblock: %w", err)
	}
	if string(super[:len(pdbMagic)]) != string(pdbMagic) {
		return nil, errors.New("not an MSF 7 PDB")
	}
	m := &msfFile{
		r:         r,
		blockSize: binary.LittleEndian.Uint32(super[32:36]),
		numBlocks: binary.LittleEndian.Uint32(super[40:44]),
	}
	switch m.blockSize {
	case 512, 1024, 2048, 4096, 8192, 16384, 32768:
	default:
		return nil, fmt.Errorf("unexpected MSF block size %d", m.blockSize)
	}
	dirBytes := binary.LittleEndian.Uint32(super[44:48])
	blockMap := binary.LittleEndian.Uint32(super[52:56])
	dirBlocks := (dirBytes + m.blockSize - 1) / m.blockSize
	if dirBlocks*4 > m.blockSize {
		return nil, errors.New("MSF stream directory is too large")
	}
	mapData, err := m.readBlock(blockMap)
	if err != nil {
		return nil, err
	}
	var dir []byte
	for i := uint32(0); i < dirBlocks; i++ {
		block, err := m.readBlock(binary.LittleEndian.Uint32(mapData[i*4:]))
		if err != nil {
			return nil, err
		}
		dir = append(dir, block...)
	}
	dir = dir[:dirBytes]
	if len(dir) < 4 {
		return nil, errors.New("MSF stream directory is empty")
	}
	count := binary.LittleEndian.Uint32(dir)
	pos := uint64(4)
	if uint64(len(dir)) < pos+uint64(count)*4 {
		return nil, errors.New("MSF stream directory is truncated")
	}
	m.sizes = make([]uint32, count)
	for i := range m.sizes {
		size := binary.LittleEndian.Uint32(dir[pos:])
		if size == 0xFFFFFFFF {
			size = 0
		}
		m.sizes[i] = size
		pos += 4
	}
	m.blockLists = make([][]uint32, count)
	for i, size := range m.sizes {
		n := (size + m.blockSize - 1) / m.blockSize
		if uint64(len(dir)) < pos+uint64(n)*4 {
			return nil, errors.New("MSF stream directory is truncated")
		}
		list := make([]uint32, n)
		for j := range list {
			list[j] = binary.LittleEndian.Uint32(dir[pos:])
			pos += 4
		}
		m.blockLists[i] = list
	}
	return m, nil
}

func (m *msfFile) readBlock(index uint32) ([]byte, error) {
	if index >= m.numBlocks {
		return nil, fmt.Errorf("MSF block %d is out of range", index)
	}
	buf := make([]byte, m.blockSize)
	if _, err := m.r.ReadAt(buf, int64(index)*int64(m.blockSize)); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf, nil
}

// stream returns up to limit bytes from the start of stream index.
func (m *msfFile) stream(index int, limit uint32) ([]byte, error) {
	if index >= len(m.sizes) {
		return nil, fmt.Errorf("stream %d does not exist", index)
	}
	want := min(m.sizes[index], limit)
	var out []byte
	for _, block := range m.blockLists[index] {
		if uint32(len(out)) >= want {
			break
		}
		data, err := m.readBlock(block)
		if err != nil {
			return nil, err
		}
		out = append(out, data...)
	}
	return out[:min(uint32(len(out)), want)], nil
}
