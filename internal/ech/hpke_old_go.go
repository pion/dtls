// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !go1.26

package ech

func Available() bool                                                     { return false }
func NewSender(Config, CipherSuite) ([]byte, Sender, error)               { return nil, nil, ErrToolchain }
func NewRecipient(Config, CipherSuite, []byte, []byte) (Recipient, error) { return nil, ErrToolchain }

func PickConfig([]Config) (*Config, CipherSuite, error) { return nil, CipherSuite{}, ErrToolchain }
