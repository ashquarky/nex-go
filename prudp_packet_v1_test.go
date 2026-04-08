package nex

import "testing"

func FuzzNewPRUDPPacketsV1(f *testing.F) {
	v1Key := make([]byte, 16)

	f.Fuzz(func(t *testing.T, packets []byte,
		legacySignature bool) {
		server := NewPRUDPServer()
		server.PRUDPv1ConnectionSignatureKey = v1Key
		server.LibraryVersions.SetDefault(NewLibraryVersion(3, 10, 0))
		server.AccessKey = "aaaaaaaa"

		server.PRUDPV1Settings.LegacyConnectionSignature = legacySignature

		stream := NewByteStreamIn(packets, server.LibraryVersions, server.ByteStreamSettings)
		_, err := NewPRUDPPacketsV1(server, nil, stream)
		if err != nil {
			t.Logf("%v", err)
			return
		}
	})
}
