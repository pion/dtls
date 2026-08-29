// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"math"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"golang.org/x/crypto/cryptobyte"
)

const sequenceNumberPlaceholder = uint64(0xffffffffffffffff)

type keyMaterial struct {
	masterSecret []byte
	clientRandom []byte
	serverRandom []byte
	role         cryptosuite.EndpointRole
}

func NewKeyMaterial(
	masterSecret, clientRandom, serverRandom []byte,
	role cryptosuite.EndpointRole,
) (cryptosuite.KeyMaterial, error) {
	if len(masterSecret) == 0 || len(clientRandom) == 0 || len(serverRandom) == 0 ||
		(role != cryptosuite.EndpointRoleClient && role != cryptosuite.EndpointRoleServer) {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}

	return keyMaterial{
		masterSecret: masterSecret,
		clientRandom: clientRandom,
		serverRandom: serverRandom,
		role:         role,
	}, nil
}

func (m keyMaterial) MasterSecret() []byte           { return m.masterSecret }
func (m keyMaterial) ClientRandom() []byte           { return m.clientRandom }
func (m keyMaterial) ServerRandom() []byte           { return m.serverRandom }
func (m keyMaterial) Role() cryptosuite.EndpointRole { return m.role }

type trafficSecret struct{ secret []byte }

func NewTrafficSecret(secret []byte) (cryptosuite.TrafficSecret, error) {
	if len(secret) == 0 {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}

	return trafficSecret{secret: secret}, nil
}

func (s trafficSecret) Bytes() []byte { return s.secret }

type protectionRecord struct {
	recordNumber       uint64
	authenticationData []byte
	protectedLen       int
	legacy             bool
}

func (r protectionRecord) RecordNumber() uint64 { return r.recordNumber }

func (r protectionRecord) AuthenticationData(recordLen int) ([]byte, error) {
	if recordLen < 0 || recordLen > math.MaxUint16 {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}
	data := bytes.Clone(r.authenticationData)
	if !r.legacy {
		if recordLen != r.protectedLen {
			return nil, dtlserrors.ErrInvalidProtectionInput
		}

		return data, nil
	}

	return append(data, byte(recordLen>>8), byte(recordLen)), nil //nolint:gosec // checked above.
}

func NewLegacyRecord(
	contentType protocol.ContentType,
	version protocol.Version,
	epoch uint16,
	sequenceNumber uint64,
	connectionID []byte,
) (cryptosuite.Record, error) {
	if contentType == 0 || version != protocol.Version1_2 ||
		sequenceNumber > recordlayer.MaxSequenceNumber || len(connectionID) > math.MaxUint8 ||
		(contentType == protocol.ContentTypeConnectionID) != (len(connectionID) > 0) {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}

	var builder cryptobyte.Builder
	if contentType == protocol.ContentTypeConnectionID {
		builder.AddUint64(sequenceNumberPlaceholder)
		builder.AddUint8(uint8(protocol.ContentTypeConnectionID))
		builder.AddUint8(uint8(len(connectionID))) //nolint:gosec // checked above.
		builder.AddUint8(uint8(protocol.ContentTypeConnectionID))
		builder.AddUint8(protocol.Version1_2.Major())
		builder.AddUint8(protocol.Version1_2.Minor())
		builder.AddUint16(epoch)
		builder.AddUint48(sequenceNumber)
		builder.AddBytes(connectionID)
	} else {
		builder.AddUint16(epoch)
		builder.AddUint48(sequenceNumber)
		builder.AddUint8(uint8(contentType))
		builder.AddUint8(protocol.Version1_2.Major())
		builder.AddUint8(protocol.Version1_2.Minor())
	}
	authenticationData, err := builder.Bytes()
	if err != nil {
		return nil, err
	}

	return protectionRecord{
		recordNumber:       uint64(epoch)<<48 | sequenceNumber,
		authenticationData: authenticationData,
		legacy:             true,
	}, nil
}

func NewUnifiedRecord( //nolint:cyclop
	epoch, sequenceNumber uint64,
	header recordlayer.UnifiedHeader,
	protectedLen int,
) (cryptosuite.Record, error) {
	if header.EpochLow > 3 || uint8(epoch&3) != header.EpochLow ||
		len(header.ConnectionID) > math.MaxUint8 || protectedLen < 0 || protectedLen > math.MaxUint16 {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}
	if header.SeqBit {
		if uint16(sequenceNumber&math.MaxUint16) != header.SequenceNumber {
			return nil, dtlserrors.ErrInvalidProtectionInput
		}
	} else if header.SequenceNumber > math.MaxUint8 ||
		uint16(sequenceNumber&math.MaxUint8) != header.SequenceNumber {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}

	if header.LengthBit {
		if header.Length != 0 && int(header.Length) != protectedLen {
			return nil, dtlserrors.ErrInvalidProtectionInput
		}
		header.Length = uint16(protectedLen) //nolint:gosec // checked above.
	}
	authenticationData, err := header.Marshal()
	if err != nil {
		return nil, err
	}

	return protectionRecord{
		recordNumber:       sequenceNumber,
		authenticationData: authenticationData,
		protectedLen:       protectedLen,
	}, nil
}
