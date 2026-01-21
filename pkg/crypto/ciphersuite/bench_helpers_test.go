//go:build bench

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import "testing"

func formatSize(b *testing.B, size int) string {
	b.Helper()

	if size < 1024 {
		return string(rune('0'+size/100)) + string(rune('0'+(size/10)%10)) + string(rune('0'+size%10)) + "B"
	} else if size < 10240 {
		kb := size / 1024
		remainder := (size % 1024) * 10 / 1024
		if remainder > 0 {
			return string(rune('0'+kb)) + "." + string(rune('0'+remainder)) + "KB"
		}

		return string(rune('0'+kb)) + "KB"
	}

	return string(rune('0'+size/1024/10)) + string(rune('0'+(size/1024)%10)) + "KB"
}
