package main

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestPayloadRejectsCorruptionAndTruncation(t *testing.T) {
	for _, data := range [][]byte{[]byte("xx!x"), []byte("xxx")} {
		r := newResult("short")
		if readPayload(bytes.NewReader(data), 4, make([]byte, 64), time.Now().Add(-time.Second), time.Now().Add(time.Second), &r) == nil {
			t.Fatal("损坏或截断的内容不能作为成功吞吐")
		}
	}
}

func TestPayloadWindowExcludesWarmupAndDrain(t *testing.T) {
	for _, shift := range []time.Duration{-2 * time.Second, 2 * time.Second} {
		r := newResult("short")
		start := time.Now().Add(shift)
		if err := readPayload(bytes.NewReader([]byte("xxxx")), 4, make([]byte, 64), start, start.Add(time.Second), &r); err != nil {
			t.Fatal(err)
		}
		if r.MeasuredBytes != 0 || r.TotalBytes != 4 {
			t.Fatalf("测量窗口混入收尾或预热字节：%+v", r)
		}
	}
	var out bytes.Buffer
	if err := payload(&out, 65539); err != nil {
		t.Fatal(err)
	}
	r := newResult("bulk")
	if err := readPayload(&out, 65539, make([]byte, 65536), time.Now().Add(-time.Second), time.Now().Add(time.Second), &r); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if r.MeasuredBytes != 65539 {
		t.Fatal(r.MeasuredBytes)
	}
}
