// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

// we'll add the flight handlers for the DTLS 1.3 client here.
//
// +----------+
// | Flight 1 |
// | Flight 3 |
// | Flight 5 |
// +----------+
//
// +-----------+
// | Flight 3a |
// | Flight 5a |
// +-----------+
//
// +-----------+
// | Flight 3b |
// | Flight 5b |
// +-----------+
//
// +-----------+
// | Flight 5c |
// +-----------+
