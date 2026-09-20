// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"encoding/binary"
	"math"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/recordwire"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/protocol"
	"golang.org/x/crypto/cryptobyte"
)

const sequenceNumberPlaceholder = uint64(0xffffffffffffffff)

type keyMaterial struct {
	masterSecret []byte
	clientRandom []byte
	serverRandom []byte
	role         cryptosuite.EndpointRole
}

func NewKeyMaterial(masterSecret, clientRandom, serverRandom []byte, role cryptosuite.EndpointRole) (cryptosuite.KeyMaterial, error) {
	if len(masterSecret) == 0 || len(clientRandom) == 0 || len(serverRandom) == 0 || (role != cryptosuite.EndpointRoleClient && role != cryptosuite.EndpointRoleServer) {
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

func NewLegacyRecord(contentType protocol.ContentType, version protocol.Version, epoch uint16, sequenceNumber uint64, connectionID []byte) (cryptosuite.Record, error) {
	if contentType == 0 || version != protocol.Version1_2 || sequenceNumber > recordwire.MaxSequenceNumber || len(connectionID) > math.MaxUint8 || (contentType == protocol.ContentTypeConnectionID) != (len(connectionID) > 0) {
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

	return protectionRecord{recordNumber: uint64(epoch)<<48 | sequenceNumber, authenticationData: authenticationData, legacy: true}, nil
}

// NewUnifiedRecord snapshots the clear, exact unified header used as AAD.
//
//nolint:cyclop
func NewUnifiedRecord(epoch, sequenceNumber uint64, header []byte, protectedLen int) (cryptosuite.Record, error) {
	if len(header) < 2 || !protocol.IsDTLS13Ciphertext(protocol.ContentType(header[0])) || protectedLen < 0 || protectedLen > math.MaxUint16 {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}
	sequenceEnd := len(header)
	if header[0]&recordwire.LengthBit != 0 {
		if len(header) < 4 || int(binary.BigEndian.Uint16(header[len(header)-2:])) != protectedLen {
			return nil, dtlserrors.ErrInvalidProtectionInput
		}
		sequenceEnd -= 2
	}
	sequenceLen := 1
	if header[0]&recordwire.SequenceBit != 0 {
		sequenceLen = 2
	}
	cidLength := sequenceEnd - sequenceLen - 1
	if cidLength < 0 || cidLength > math.MaxUint8 || (header[0]&recordwire.CIDBit != 0) != (cidLength != 0) || uint8(epoch&3) != header[0]&recordwire.EpochMask {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}
	for i := 0; i < sequenceLen; i++ {
		if header[sequenceEnd-1-i] != byte((sequenceNumber>>uint(8*i))&0xff) {
			return nil, dtlserrors.ErrInvalidProtectionInput
		}
	}

	return protectionRecord{recordNumber: sequenceNumber, authenticationData: bytes.Clone(header), protectedLen: protectedLen}, nil
}
