// Copyright (C) 2026 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/syncthing/syncthing/lib/protocol"
)

func TestQUICWechatVideoMaskingIsPerDevice(t *testing.T) {
	myID := protocol.NewDeviceID([]byte("local device certificate"))
	cfg := New(myID)
	if cfg.Defaults.Device.QUICWechatVideoMasking {
		t.Fatal("QUIC WeChat masking is enabled in defaults")
	}
	cfg.Defaults.Device.QUICWechatVideoMasking = true
	if err := cfg.prepare(myID); err != nil {
		t.Fatal(err)
	}
	if cfg.Defaults.Device.QUICWechatVideoMasking {
		t.Fatal("QUIC WeChat masking must not be inherited from global defaults")
	}

	// Also cover JSON input where the defaults object is explicitly enabled,
	// while the device object omits this device-only field altogether.
	cfg.Defaults.Device.QUICWechatVideoMasking = true
	cfg.Devices[0].QUICWechatVideoMasking = false
	jsonConfig, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(jsonConfig, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw["devices"].([]any)[0].(map[string]any), "quicWechatVideoMasking")
	jsonConfig, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	decodedWithoutDeviceSetting, err := ReadJSON(bytes.NewReader(jsonConfig), myID)
	if err != nil {
		t.Fatal(err)
	}
	if decodedWithoutDeviceSetting.Devices[0].QUICWechatVideoMasking {
		t.Fatal("device-only masking setting was inherited from JSON defaults")
	}

	cfg.Devices[0].QUICWechatVideoMasking = true
	jsonConfig, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadJSON(bytes.NewReader(jsonConfig), myID)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Devices[0].QUICWechatVideoMasking {
		t.Fatal("device masking setting was not preserved through JSON")
	}

	var xmlConfig bytes.Buffer
	if err := cfg.WriteXML(&xmlConfig); err != nil {
		t.Fatal(err)
	}
	decodedXML, _, err := ReadXML(bytes.NewReader(xmlConfig.Bytes()), myID)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedXML.Devices[0].QUICWechatVideoMasking {
		t.Fatal("device masking setting was not preserved through XML")
	}
}
