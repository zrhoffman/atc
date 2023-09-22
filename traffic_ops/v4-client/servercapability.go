package client

/*

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

import (
	"net/url"

	"github.com/apache/trafficcontrol/v8/lib/go-tc"
	"github.com/apache/trafficcontrol/v8/traffic_ops/toclientlib"
)

// apiServerCapabilities is the full path to the /server_capabilities API
// endpoint.
const apiServerCapabilities = "/server_capabilities"

// CreateServerCapability creates the given Server Capability.
// Note: Call Signature changed in v5, accepts tc.ServerCapabilityV41 instead of tc.ServerCapability
func (to *Session) CreateServerCapability(sc tc.ServerCapability, opts RequestOptions) (tc.ServerCapabilityDetailResponse, toclientlib.ReqInf, error) {
	var scResp tc.ServerCapabilityDetailResponse
	reqInf, err := to.post(apiServerCapabilities, opts, sc, &scResp)
	return scResp, reqInf, err
}

// CreateServerCapabilityV41 creates the given Server Capability V41 (includes description).
func (to *Session) CreateServerCapabilityV41(sc tc.ServerCapabilityV41, opts RequestOptions) (tc.ServerCapabilityDetailResponseV41, toclientlib.ReqInf, error) {
	var scResp tc.ServerCapabilityDetailResponseV41
	reqInf, err := to.post(apiServerCapabilities, opts, sc, &scResp)
	return scResp, reqInf, err
}

// GetServerCapabilities returns all the Server Capabilities in Traffic Ops.
// Note: Call Signature changed in v5, accepts tc.ServerCapabilitiesResponseV41 instead of tc.ServerCapabilitiesResponse
func (to *Session) GetServerCapabilities(opts RequestOptions) (tc.ServerCapabilitiesResponse, toclientlib.ReqInf, error) {
	var data tc.ServerCapabilitiesResponse
	reqInf, err := to.get(apiServerCapabilities, opts, &data)
	return data, reqInf, err
}

// GetServerCapabilitiesV41 returns all the Server Capabilities V41 (includes description) in Traffic Ops.
func (to *Session) GetServerCapabilitiesV41(opts RequestOptions) (tc.ServerCapabilitiesResponseV41, toclientlib.ReqInf, error) {
	var data tc.ServerCapabilitiesResponseV41
	reqInf, err := to.get(apiServerCapabilities, opts, &data)
	return data, reqInf, err
}

// UpdateServerCapability updates a Server Capability by name.
// Note: Call Signature changed in v5, accepts tc.ServerCapabilityV41 instead of tc.ServerCapability
func (to *Session) UpdateServerCapability(name string, sc tc.ServerCapability, opts RequestOptions) (tc.ServerCapabilityDetailResponse, toclientlib.ReqInf, error) {
	if opts.QueryParameters == nil {
		opts.QueryParameters = url.Values{}
	}
	opts.QueryParameters.Set("name", name)
	var data tc.ServerCapabilityDetailResponse
	reqInf, err := to.put(apiServerCapabilities, opts, sc, &data)
	return data, reqInf, err
}

// UpdateServerCapabilityV41 updates a Server Capability V41 (includes description) by name.
func (to *Session) UpdateServerCapabilityV41(name string, sc tc.ServerCapabilityV41, opts RequestOptions) (tc.ServerCapabilityDetailResponseV41, toclientlib.ReqInf, error) {
	if opts.QueryParameters == nil {
		opts.QueryParameters = url.Values{}
	}
	opts.QueryParameters.Set("name", name)
	var data tc.ServerCapabilityDetailResponseV41
	reqInf, err := to.put(apiServerCapabilities, opts, sc, &data)
	return data, reqInf, err
}

// DeleteServerCapability deletes the given server capability by name.
func (to *Session) DeleteServerCapability(name string, opts RequestOptions) (tc.Alerts, toclientlib.ReqInf, error) {
	if opts.QueryParameters == nil {
		opts.QueryParameters = url.Values{}
	}
	opts.QueryParameters.Set("name", name)
	var alerts tc.Alerts
	reqInf, err := to.del(apiServerCapabilities, opts, &alerts)
	return alerts, reqInf, err
}
