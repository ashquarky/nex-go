package nex

import "testing"

func FuzzNewPRUDPPacketsV0(f *testing.F) {
	f.Fuzz(func(t *testing.T, packets []byte,
		checksums bool, enhancedChecksums bool, quazalMode bool, legacySignature bool, encryptedConnect bool) {

		server := NewPRUDPServer()
		server.LibraryVersions.SetDefault(NewLibraryVersion(3, 10, 0))
		if checksums {
			server.AccessKey = "aaaaaaaa"
		} else {
			server.AccessKey = "ridfebb9" // disables all the checksums
		}

		server.PRUDPV0Settings.UseEnhancedChecksum = enhancedChecksums
		server.PRUDPV0Settings.IsQuazalMode = quazalMode
		server.PRUDPV0Settings.LegacyConnectionSignature = legacySignature
		server.PRUDPV0Settings.EncryptedConnect = encryptedConnect

		stream := NewByteStreamIn(packets, server.LibraryVersions, server.ByteStreamSettings)
		_, err := NewPRUDPPacketsV0(server, nil, stream)
		if err != nil {
			t.Logf("%v", err)
			return
		}
	})
}
