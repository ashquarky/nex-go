package nex

import (
	"net"
	"strconv"
	"testing"

	"github.com/PretendoNetwork/nex-go/v2/compression"
	"github.com/PretendoNetwork/nex-go/v2/encryption"
	"github.com/PretendoNetwork/nex-go/v2/types"
)

func FuzzPRUDPServer_handleSocketMessage(f *testing.F) {
	v1Key := make([]byte, 16)
	kerberosPass := string(make([]byte, 16))
	authServerAccount := NewAccount(types.NewPID(1), "Quazal Authentication", kerberosPass, false)
	secureServerAccount := NewAccount(types.NewPID(2), "Quazal Rendez-Vous", kerberosPass, false)

	f.Fuzz(func(t *testing.T, packets []byte,
		secure bool, checksums bool, enhancedChecksums bool, quazalMode bool, legacySignature bool,
		encryptedConnect bool, verboseRMC bool, dummyEncrypt bool, compress bool, lzo bool) {
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
		server.UseVerboseRMC = verboseRMC

		endpoint := NewPRUDPEndPoint(1)
		if dummyEncrypt {
			endpoint.DefaultStreamSettings.EncryptionAlgorithm = encryption.NewDummyEncryption()
		}
		if compress && lzo {
			endpoint.DefaultStreamSettings.CompressionAlgorithm = compression.NewLZOCompression()
		} else if compress {
			endpoint.DefaultStreamSettings.CompressionAlgorithm = compression.NewZlibCompression()
		}
		endpoint.IsSecureEndPoint = secure
		if secure {
			endpoint.ServerAccount = secureServerAccount
		} else {
			endpoint.ServerAccount = authServerAccount
		}
		endpoint.AccountDetailsByUsername = func(username string) (*Account, *Error) {
			if username == authServerAccount.Username {
				return authServerAccount, nil
			}
			if username == secureServerAccount.Username {
				return secureServerAccount, nil
			}

			pidInt, err := strconv.Atoi(username)
			if err != nil {
				t.Logf("%v", err)
				return nil, NewError(ResultCodes.RendezVous.InvalidUsername, "Invalid username")
			}

			pid := types.NewPID(uint64(pidInt))

			account := NewAccount(pid, username, "AAAAAAAAAAAAAAAA", false)

			return account, nil
		}
		endpoint.AccountDetailsByPID = func(pid types.PID) (*Account, *Error) {
			if pid.Equals(authServerAccount.PID) {
				return authServerAccount, nil
			}
			if pid.Equals(secureServerAccount.PID) {
				return secureServerAccount, nil
			}

			account := NewAccount(pid, strconv.Itoa(int(pid)), "AAAAAAAAAAAAAAAA", false)

			return account, nil
		}
		server.BindPRUDPEndPoint(endpoint)

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
