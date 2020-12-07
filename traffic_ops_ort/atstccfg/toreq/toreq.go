// toreqnew implements a Traffic Ops client vendored one version back.
//
// This should be used for all requests, unless they require an endpoint or field added in the latest version.
//
// If a feature in the latest Traffic Ops is required, toreqnew should be used with a fallback to this client if the Traffic Ops is not the latest (which can be determined by the bool returned by all toreqnew.TOClient funcs).
//
package toreq

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/apache/trafficcontrol/lib/go-atscfg"
	"github.com/apache/trafficcontrol/lib/go-log"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/lib/go-util"
	toclient "github.com/apache/trafficcontrol/traffic_ops/v1-client"
	"github.com/apache/trafficcontrol/traffic_ops_ort/atstccfg/torequtil"
)

type TOClient struct {
	C          *toclient.Session
	NumRetries int
}

// New logs into Traffic Ops, returning the TOClient which contains the logged-in client.
func New(url *url.URL, user string, pass string, insecure bool, timeout time.Duration, userAgent string) (*TOClient, error) {
	log.Infoln("URL: '" + url.String() + "' User: '" + user + "' Pass len: '" + strconv.Itoa(len(pass)) + "'")

	toFQDN := url.Scheme + "://" + url.Host
	log.Infoln("TO FQDN: '" + toFQDN + "'")
	log.Infoln("TO URL: '" + url.String() + "'")

	toClient, toIP, err := toclient.LoginWithAgent(toFQDN, user, pass, insecure, userAgent, false, timeout)
	if err != nil {
		return nil, errors.New("Logging in to Traffic Ops '" + MaybeIPStr(toIP) + "': " + err.Error())
	}

	return &TOClient{C: toClient}, nil
}

// Cookies returns the HTTP session cookies from the client.
// It does not do any kind of validation, but assumes the HTTP cookies exist from a prior login and are valid for a Traffic Ops session.
// The url is the Traffic Ops URL, and should match this client's Traffic Ops URL, and the URL of the new client this session cookie is presumably being fetched for.
func (cl *TOClient) Cookies(url *url.URL) string {
	return torequtil.CookiesToString(cl.C.Client.Jar.Cookies(url))
}

// MaybeIPStr returns the addr string if it isn't nil, or the empty string if it is.
// This is intended for logging, to allow logging with one line, whether addr is nil or not.
func MaybeIPStr(addr net.Addr) string {
	if addr != nil {
		return addr.String()
	}
	return ""
}

func (cl *TOClient) GetProfileByName(profileName string) (tc.Profile, net.Addr, error) {
	profile := tc.Profile{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "profile_"+profileName, &profile, func(obj interface{}) error {
		toProfiles, reqInf, err := cl.C.GetProfileByName(profileName)
		if err != nil {
			return errors.New("getting profile '" + profileName + "' from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		if len(toProfiles) != 1 {
			return errors.New("getting profile '" + profileName + "'from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': expected 1 Profile, got " + strconv.Itoa(len(toProfiles)))
		}

		profile := obj.(*tc.Profile)
		*profile = toProfiles[0]
		toAddr = reqInf.RemoteAddr
		return nil
	})

	if err != nil {
		return tc.Profile{}, nil, errors.New("getting profile '" + profileName + "': " + err.Error())
	}
	return profile, toAddr, nil
}

func (cl *TOClient) GetGlobalParameters() ([]tc.Parameter, net.Addr, error) {
	globalParams := []tc.Parameter{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "profile_global_parameters", &globalParams, func(obj interface{}) error {
		toParams, reqInf, err := cl.C.GetParametersByProfileName(tc.GlobalProfileName)
		if err != nil {
			return errors.New("getting global profile '" + tc.GlobalProfileName + "' parameters from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		params := obj.(*[]tc.Parameter)
		*params = toParams
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting global profile '" + tc.GlobalProfileName + "' parameters: " + err.Error())
	}
	return globalParams, toAddr, nil
}

func GetTOToolNameAndURL(globalParams []tc.Parameter) (string, string) {
	// TODO move somewhere generic
	toToolName := ""
	toURL := ""
	for _, param := range globalParams {
		if param.Name == "tm.toolname" {
			toToolName = param.Value
		} else if param.Name == "tm.url" {
			toURL = param.Value
		}
		if toToolName != "" && toURL != "" {
			break
		}
	}
	// TODO error here? Perl doesn't.
	if toToolName == "" {
		log.Warnln("Global Parameter tm.toolname not found, config may not be constructed properly!")
	}
	if toURL == "" {
		log.Warnln("Global Parameter tm.url not found, config may not be constructed properly!")
	}
	return toToolName, toURL
}

func (cl *TOClient) GetServers() ([]atscfg.Server, net.Addr, error) {
	servers := []atscfg.Server{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "servers", &servers, func(obj interface{}) error {
		toServers, reqInf, err := cl.C.GetServers()
		if err != nil {
			return errors.New("getting servers from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		servers := obj.(*[]atscfg.Server)
		*servers, err = serversToLatest(toServers)
		if err != nil {
			return errors.New("upgrading servers from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting servers: " + err.Error())
	}
	return servers, toAddr, nil
}

// serversToLatest converts a []tc.Server to []tc.ServerV30.
// This is necessary, because the Traffic Ops API 1.x client doesn't return the same type as the latest client.
func serversToLatest(svs []tc.ServerV1) ([]atscfg.Server, error) {
	nss := []atscfg.Server{}
	for _, sv := range svs {
		svLatest, err := serverToLatest(&sv)
		if err != nil {
			return nil, err // serverToLatest adds context
		}
		nss = append(nss, atscfg.Server(*svLatest))
	}
	return nss, nil
}

// serverToLatest converts a tc.Server to tc.ServerV30.
// This is necessary, because the Traffic Ops API 1.x client doesn't return the same type as the latest client.
func serverToLatest(sv *tc.ServerV1) (*atscfg.Server, error) {
	svn := sv.ToNullable()
	sv2 := tc.ServerNullableV2{
		ServerNullableV11: svn,
		IPIsService:       util.BoolPtr(true),
		IP6IsService:      util.BoolPtr(svn.IP6Address != nil && *svn.IP6Address != ""),
	}
	svLatest, err := sv2.Upgrade()
	if err != nil {
		return nil, errors.New("upgrading: " + err.Error())
	}
	asv := atscfg.Server(svLatest)
	return &asv, nil
}

func (cl *TOClient) GetServerByHostName(serverHostName string) (*atscfg.Server, net.Addr, error) {
	server := atscfg.Server{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "server-name-"+serverHostName, &server, func(obj interface{}) error {
		toServers, reqInf, err := cl.C.GetServerByHostName(serverHostName)
		if err != nil {
			return errors.New("getting server name '" + serverHostName + "' from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		} else if len(toServers) < 1 {
			return errors.New("getting server name '" + serverHostName + "' from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': no servers returned")
		}
		asv, err := serverToLatest(&toServers[0])
		if err != nil {
			return errors.New("converting server to latest version: " + err.Error())
		}
		server := obj.(*atscfg.Server)
		*server = *asv
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting server name '" + serverHostName + "': " + err.Error())
	}
	return &server, toAddr, nil
}

func (cl *TOClient) GetCacheGroups() ([]tc.CacheGroupNullable, net.Addr, error) {
	cacheGroups := []tc.CacheGroupNullable{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "cachegroups", &cacheGroups, func(obj interface{}) error {
		toCacheGroups, reqInf, err := cl.C.GetCacheGroupsNullable()
		if err != nil {
			return errors.New("getting cachegroups from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		cacheGroups := obj.(*[]tc.CacheGroupNullable)
		*cacheGroups = toCacheGroups
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting cachegroups: " + err.Error())
	}
	return cacheGroups, toAddr, nil
}

// DeliveryServiceServersAlwaysGetAll indicates whether to always get all delivery service servers from Traffic Ops, and cache all in a file (but still return to the caller only the objects they requested).
// This exists and is currently true, because with an ORT run, it's typically more efficient to get them all in a single request, and re-use that cache; than for every config file to get and cache its own unique set.
// If your use case is more efficient to only get the needed objects, for example if you're frequently requesting one file, set this false to get and cache the specific needed delivery services and servers.
const DeliveryServiceServersAlwaysGetAll = true

func (cl *TOClient) GetDeliveryServiceServers(dsIDs []int, serverIDs []int) ([]tc.DeliveryServiceServer, net.Addr, error) {
	const sortIDsInHash = true
	toAddr := net.Addr(nil)
	serverIDsStr := ""
	dsIDsStr := ""
	dsIDsToFetch := ([]int)(nil)
	sIDsToFetch := ([]int)(nil)
	if !DeliveryServiceServersAlwaysGetAll {
		if len(dsIDs) > 0 {
			dsIDsStr = base64.RawURLEncoding.EncodeToString((util.HashInts(dsIDs, sortIDsInHash)))
		}
		if len(serverIDs) > 0 {
			serverIDsStr = base64.RawURLEncoding.EncodeToString((util.HashInts(serverIDs, sortIDsInHash)))
		}
		dsIDsToFetch = dsIDs
		sIDsToFetch = serverIDs
	}

	dsServers := []tc.DeliveryServiceServer{}
	err := torequtil.GetRetry(cl.NumRetries, "deliveryservice_servers_s"+serverIDsStr+"_d_"+dsIDsStr, &dsServers, func(obj interface{}) error {
		const noLimit = 999999 // TODO add "no limit" param to DSS endpoint
		toDSS, reqInf, err := cl.C.GetDeliveryServiceServersWithLimits(noLimit, dsIDsToFetch, sIDsToFetch)
		if err != nil {
			return errors.New("getting delivery service servers from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		dss := obj.(*[]tc.DeliveryServiceServer)
		*dss = toDSS.Response
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting delivery service servers: " + err.Error())
	}

	serverIDsMap := map[int]struct{}{}
	for _, id := range serverIDs {
		serverIDsMap[id] = struct{}{}
	}
	dsIDsMap := map[int]struct{}{}
	for _, id := range dsIDs {
		dsIDsMap[id] = struct{}{}
	}

	// Older TO's may ignore the server ID list, so we need to filter them out manually to be sure.
	// Also, if DeliveryServiceServersAlwaysGetAll, we need to filter here anyway.
	filteredDSServers := []tc.DeliveryServiceServer{}
	for _, dsServer := range dsServers {
		if dsServer.Server == nil || dsServer.DeliveryService == nil {
			continue // TODO warn? error?
		}
		if len(serverIDsMap) > 0 {
			if _, ok := serverIDsMap[*dsServer.Server]; !ok {
				continue
			}
		}
		if len(dsIDsMap) > 0 {
			if _, ok := dsIDsMap[*dsServer.DeliveryService]; !ok {
				continue
			}
		}
		filteredDSServers = append(filteredDSServers, dsServer)
	}

	return filteredDSServers, toAddr, nil
}

func (cl *TOClient) GetServerProfileParameters(profileName string) ([]tc.Parameter, net.Addr, error) {
	serverProfileParameters := []tc.Parameter{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "profile_"+profileName+"_parameters", &serverProfileParameters, func(obj interface{}) error {
		toParams, reqInf, err := cl.C.GetParametersByProfileName(profileName)
		if err != nil {
			return errors.New("getting server profile '" + profileName + "' parameters from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		params := obj.(*[]tc.Parameter)
		*params = toParams
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting server profile '" + profileName + "' parameters: " + err.Error())
	}
	return serverProfileParameters, toAddr, nil
}

func (cl *TOClient) GetCDNDeliveryServices(cdnID int) ([]atscfg.DeliveryService, net.Addr, error) {
	deliveryServices := []atscfg.DeliveryService{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "cdn_"+strconv.Itoa(cdnID)+"_deliveryservices", &deliveryServices, func(obj interface{}) error {
		toDSes, reqInf, err := cl.C.GetDeliveryServicesByCDNID(cdnID)
		if err != nil {
			return errors.New("getting delivery services from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		dses := obj.(*[]atscfg.DeliveryService)
		*dses = atscfg.OldToDeliveryServices(toDSes)
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting delivery services: " + err.Error())
	}
	return deliveryServices, toAddr, nil
}

func (cl *TOClient) GetConfigFileParameters(configFile string) ([]tc.Parameter, net.Addr, error) {
	params := []tc.Parameter{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "config_file_"+configFile+"_parameters", &params, func(obj interface{}) error {
		toParams, reqInf, err := cl.C.GetParameterByConfigFile(configFile)
		if err != nil {
			return errors.New("getting delivery services from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		params := obj.(*[]tc.Parameter)
		*params = toParams
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting parent.config parameters: " + err.Error())
	}
	return params, toAddr, nil
}

func (cl *TOClient) GetCDN(cdnName tc.CDNName) (tc.CDN, net.Addr, error) {
	cdn := tc.CDN{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "cdn_"+string(cdnName), &cdn, func(obj interface{}) error {
		toCDNs, reqInf, err := cl.C.GetCDNByName(string(cdnName))
		if err != nil {
			return errors.New("getting cdn from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		if len(toCDNs) != 1 {
			return errors.New("getting cdn from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': expected 1 CDN, got " + strconv.Itoa(len(toCDNs)))
		}
		cdn := obj.(*tc.CDN)
		*cdn = toCDNs[0]
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return tc.CDN{}, nil, errors.New("getting cdn: " + err.Error())
	}
	return cdn, toAddr, nil
}

func (cl *TOClient) GetURLSigKeys(dsName string) (tc.URLSigKeys, net.Addr, error) {
	keys := tc.URLSigKeys{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "urlsigkeys_"+string(dsName), &keys, func(obj interface{}) error {
		toKeys, reqInf, err := cl.C.GetDeliveryServiceURLSigKeys(dsName)
		if err != nil {
			return errors.New("getting url sig keys from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		keys := obj.(*tc.URLSigKeys)
		*keys = toKeys
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return tc.URLSigKeys{}, nil, errors.New("getting url sig keys: " + err.Error())
	}
	return keys, toAddr, nil
}

func (cl *TOClient) GetURISigningKeys(dsName string) ([]byte, net.Addr, error) {
	keys := []byte{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "urisigningkeys_"+string(dsName), &keys, func(obj interface{}) error {
		toKeys, reqInf, err := cl.C.GetDeliveryServiceURISigningKeys(dsName)
		if err != nil {
			return errors.New("getting url sig keys from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}

		keys := obj.(*[]byte)
		*keys = toKeys
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return []byte{}, nil, errors.New("getting url sig keys: " + err.Error())
	}
	return keys, toAddr, nil
}

func (cl *TOClient) GetParametersByName(paramName string) ([]tc.Parameter, net.Addr, error) {
	params := []tc.Parameter{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "parameters_name_"+paramName, &params, func(obj interface{}) error {
		toParams, reqInf, err := cl.C.GetParameterByName(paramName)
		if err != nil {
			return errors.New("getting parameters name '" + paramName + "' from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		params := obj.(*[]tc.Parameter)
		*params = toParams
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting params name '" + paramName + "': " + err.Error())
	}
	return params, toAddr, nil
}

func (cl *TOClient) GetDeliveryServiceRegexes() ([]tc.DeliveryServiceRegexes, net.Addr, error) {
	regexes := []tc.DeliveryServiceRegexes{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "ds_regexes", &regexes, func(obj interface{}) error {
		toRegexes, reqInf, err := cl.C.GetDeliveryServiceRegexes()
		if err != nil {
			return errors.New("getting ds regexes from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		regexes := obj.(*[]tc.DeliveryServiceRegexes)
		*regexes = toRegexes
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting ds regexes: " + err.Error())
	}
	return regexes, toAddr, nil
}

func (cl *TOClient) GetJobs() ([]tc.Job, net.Addr, error) {
	jobs := []tc.Job{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "jobs", &jobs, func(obj interface{}) error {
		toJobs, reqInf, err := cl.C.GetJobs(nil, nil)
		if err != nil {
			return errors.New("getting jobs from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		jobs := obj.(*[]tc.Job)
		*jobs = toJobs
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting jobs: " + err.Error())
	}
	return jobs, toAddr, nil
}

func (cl *TOClient) GetServerCapabilitiesByID(serverIDs []int) (map[int]map[atscfg.ServerCapability]struct{}, net.Addr, error) {
	serverIDsStr := ""
	if len(serverIDs) > 0 {
		sortIDsInHash := true
		serverIDsStr = base64.RawURLEncoding.EncodeToString((util.HashInts(serverIDs, sortIDsInHash)))
	}

	serverCaps := map[int]map[atscfg.ServerCapability]struct{}{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "server_capabilities_s_"+serverIDsStr, &serverCaps, func(obj interface{}) error {
		// TODO add list of IDs to API+Client
		toServerCaps, reqInf, err := cl.C.GetServerServerCapabilities(nil, nil, nil)
		if err != nil {
			return errors.New("getting server caps from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		serverCaps := obj.(*map[int]map[atscfg.ServerCapability]struct{})

		for _, sc := range toServerCaps {
			if sc.ServerID == nil {
				log.Errorln("Traffic Ops returned Server Capability with nil server id! Skipping!")
			}
			if sc.ServerCapability == nil {
				log.Errorln("Traffic Ops returned Server Capability with nil capability! Skipping!")
			}
			if _, ok := (*serverCaps)[*sc.ServerID]; !ok {
				(*serverCaps)[*sc.ServerID] = map[atscfg.ServerCapability]struct{}{}
			}
			(*serverCaps)[*sc.ServerID][atscfg.ServerCapability(*sc.ServerCapability)] = struct{}{}
		}
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting server server capabilities: " + err.Error())
	}
	return serverCaps, toAddr, nil
}

func (cl *TOClient) GetDeliveryServiceRequiredCapabilitiesByID(dsIDs []int) (map[int]map[atscfg.ServerCapability]struct{}, net.Addr, error) {
	dsIDsStr := ""
	if len(dsIDs) > 0 {
		sortIDsInHash := true
		dsIDsStr = base64.RawURLEncoding.EncodeToString((util.HashInts(dsIDs, sortIDsInHash)))
	}

	dsCaps := map[int]map[atscfg.ServerCapability]struct{}{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "ds_capabilities_d_"+dsIDsStr, &dsCaps, func(obj interface{}) error {
		// TODO add list of IDs to API+Client
		toDSCaps, reqInf, err := cl.C.GetDeliveryServicesRequiredCapabilities(nil, nil, nil)
		if err != nil {
			return errors.New("getting ds caps from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		dsCaps := obj.(*map[int]map[atscfg.ServerCapability]struct{})

		for _, sc := range toDSCaps {
			if sc.DeliveryServiceID == nil {
				log.Errorln("Traffic Ops returned Delivery Service Capability with nil ds id! Skipping!")
			}
			if sc.RequiredCapability == nil {
				log.Errorln("Traffic Ops returned Delivery Service Capability with nil capability! Skipping!")
			}
			if (*dsCaps)[*sc.DeliveryServiceID] == nil {
				(*dsCaps)[*sc.DeliveryServiceID] = map[atscfg.ServerCapability]struct{}{}
			}
			(*dsCaps)[*sc.DeliveryServiceID][atscfg.ServerCapability(*sc.RequiredCapability)] = struct{}{}
		}
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting ds server capabilities: " + err.Error())
	}
	return dsCaps, toAddr, nil
}

func (cl *TOClient) GetCDNSSLKeys(cdnName tc.CDNName) ([]tc.CDNSSLKeys, net.Addr, error) {
	keys := []tc.CDNSSLKeys{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "cdn_sslkeys_"+string(cdnName), &keys, func(obj interface{}) error {
		toKeys, reqInf, err := cl.C.GetCDNSSLKeys(string(cdnName))
		if err != nil {
			return errors.New("getting cdn ssl keys from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		keys := obj.(*[]tc.CDNSSLKeys)
		*keys = toKeys
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return []tc.CDNSSLKeys{}, nil, errors.New("getting cdn ssl keys: " + err.Error())
	}
	return keys, toAddr, nil
}

func (cl *TOClient) GetStatuses() ([]tc.Status, net.Addr, error) {
	statuses := []tc.Status{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "statuses", &statuses, func(obj interface{}) error {
		toStatus, reqInf, err := cl.C.GetStatuses()
		if err != nil {
			return errors.New("getting server update status from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		status := obj.(*[]tc.Status)
		*status = toStatus
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("getting server update status: " + err.Error())
	}
	return statuses, toAddr, nil
}

func (cl *TOClient) GetServerUpdateStatus(cacheHostName tc.CacheName) (tc.ServerUpdateStatus, net.Addr, error) {
	status := tc.ServerUpdateStatus{}
	toAddr := net.Addr(nil)
	err := torequtil.GetRetry(cl.NumRetries, "server_update_status_"+string(cacheHostName), &status, func(obj interface{}) error {
		toStatus, reqInf, err := cl.C.GetServerUpdateStatus(string(cacheHostName))
		if err != nil {
			return errors.New("getting server update status from Traffic Ops '" + MaybeIPStr(reqInf.RemoteAddr) + "': " + err.Error())
		}
		status := obj.(*tc.ServerUpdateStatus)
		*status = toStatus
		toAddr = reqInf.RemoteAddr
		return nil
	})
	if err != nil {
		return tc.ServerUpdateStatus{}, nil, errors.New("getting server update status: " + err.Error())
	}
	return status, toAddr, nil
}
