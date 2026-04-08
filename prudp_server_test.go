package nex

import (
	"net"
	"testing"
)

func FuzzPRUDPServer_handleSocketMessage(f *testing.F) {
	v1Key := make([]byte, 16)

	f.Fuzz(func(t *testing.T, packets []byte,
		secure bool, checksums bool, enhancedChecksums bool, quazalMode bool, legacySignature bool, encryptedConnect bool) {
		server := NewPRUDPServer()
		server.PRUDPv1ConnectionSignatureKey = v1Key
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
		server.PRUDPV1Settings.LegacyConnectionSignature = legacySignature

		endpoint := NewPRUDPEndPoint(1)
		endpoint.IsSecureEndPoint = secure

		udpAddress, err := net.ResolveUDPAddr("udp", "127.0.0.1:6969")
		if err != nil {
			panic(err)
		}

		err = server.handleSocketMessage(packets, udpAddress, nil)
		if err != nil {
			t.Logf("%v", err)
			return
		}

		keys := make([]string, endpoint.Connections.Size())
		i := 0
		endpoint.Connections.Each(func(key string, _ *PRUDPConnection) bool {
			keys[i] = key
			i++
			return false
		})

		for i := range keys {
			conn, ok := endpoint.Connections.Get(keys[i])
			if !ok {
				continue
			}
			endpoint.CleanupConnection(conn)
		}
	})
}
