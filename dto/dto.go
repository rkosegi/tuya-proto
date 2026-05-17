/*
Copyright 2026 Richard Kosegi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dto

type DeviceBeacon33 struct {
	Ip     string `json:"ip"`
	GwId   string `json:"gwId"`
	Active int    `json:"active"`
	// ablilty? wath? wtah?
	Ablilty    int    `json:"ablilty"`
	Encrypt    bool   `json:"encrypt"`
	ProductKey string `json:"productKey"`
	Version    string `json:"version"`
}

type DeviceBeacon34 struct {
	DeviceBeacon33
	Token bool `json:"token"`
	WfCfg bool `json:"wf_cfg"`
}

type DpsMap map[string]interface{}

type DpsWrapper struct {
	DpsMap DpsMap `json:"dps"`
}

type DpsPowerPlug struct {
	SwitchOn bool `json:"1"`
	Current  int  `json:"18"`
	Power    int  `json:"19"`
	Voltage  int  `json:"20"`
}

type DpQueryResponse struct {
	Dps DpsMap `json:"dps"`
}

type DpQueryRequest struct {
	GwId  string `json:"gwId,omitempty"`
	DevId string `json:"devId,omitempty"`
}

type ProtoStats struct {
	ReadPkts int64
	ReadErrs int64
	SentPkts int64
	SentErrs int64
}
