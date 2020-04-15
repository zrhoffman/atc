package v1

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
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/apache/trafficcontrol/lib/go-util"

	"github.com/apache/trafficcontrol/lib/go-tc"
)

const ipAllow = "ip_allow.config"

var (
	expectedRules = []string{
		"src_ip=127.0.0.1 action=ip_allow method=ALL\n",
		"src_ip=::1 action=ip_allow method=ALL\n",
	}
	midExpectedRules = []string{
		"src_ip=10.0.0.0-10.255.255.255 action=ip_allow method=ALL\n",
		"src_ip=172.16.0.0-172.31.255.255 action=ip_allow method=ALL\n",
		"src_ip=192.168.0.0-192.168.255.255 action=ip_allow method=ALL\n",
		"src_ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff action=ip_deny method=ALL\n",
		"src_ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff action=ip_deny method=ALL\n",
	}
	edgeExpectedRules = []string{
		"src_ip=0.0.0.0-255.255.255.255 action=ip_deny method=PUSH|PURGE|DELETE\n",
		"src_ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff action=ip_deny method=PUSH|PURGE|DELETE\n",
	}
	rascalServerIP = ""
	rascalRule     = "src_ip=%v action=ip_allow method=ALL"
)

func TestIPAllowDotConfig(t *testing.T) {
	WithObjs(t, []TCObj{CDNs, Types, Tenants, Parameters, Profiles, Statuses, Divisions, Regions, PhysLocations, CacheGroups, Servers, DeliveryServices}, func() {
		rascalServerIP = getServer(t, "RASCAL").IPAddress
		// rascalRule = fmt.Sprintf("src_ip=%v action=ip_allow method=ALL", rascalServer.IPAddress)
		GetTestIPAllowDotConfig(t)
		GetTestIPAllowMidDotConfig(t)
	})
}

func GetTestIPAllowDotConfig(t *testing.T) {
	// Get edge server
	s := getServer(t, "EDGE")
	output, _, err := TOSession.GetATSServerConfig(s.ID, ipAllow)
	if err != nil {
		t.Fatalf("cannot GET server %v config %v: %v", s.HostName, ipAllow, err)
	}
	for _, r := range append(expectedRules, edgeExpectedRules...) {
		if !strings.Contains(output, r) {
			t.Errorf("expected rule %v not found in ip_allow config", r)
		}
	}
	// Make sure edge does not contain rule for rascal server
	exists, ipRange := getIPRule(output, rascalServerIP)
	rascalRule := fmt.Sprintf(rascalRule, ipRange)
	if exists && strings.Contains(output, rascalRule) {
		t.Errorf("rascal IP was not supposed to be in an allowed rule: %v", rascalRule)
	}
}

func GetTestIPAllowMidDotConfig(t *testing.T) {
	// Get mid server
	s := getServer(t, "MID")
	output, _, err := TOSession.GetATSServerConfig(s.ID, ipAllow)
	if err != nil {
		t.Errorf("cannot GET server %v config %v: %v", s.HostName, ipAllow, err)
	}
	for _, r := range append(expectedRules, midExpectedRules...) {
		if !strings.Contains(output, r) {
			t.Errorf("expected rule %v not found in ip_allow config", r)
		}
	}

	// Make sure mid contains an allowed rule that includes the rascal server
	exists, ipRange := getIPRule(output, rascalServerIP)
	rascalRule := fmt.Sprintf(rascalRule, ipRange)
	if !(exists && strings.Contains(output, rascalRule)) {
		t.Errorf("expected rascal to be include as allowed in mid ip allow config")
	}
}

func getServer(t *testing.T, serverType string) tc.ServerV1 {
	v := url.Values{}
	v.Add("type", serverType)
	servers, _, err := TOSession.GetServersByType(v)
	if err != nil {
		t.Fatalf("cannot GET Server by type %v: %v", serverType, err)
	}
	if len(servers) == 0 {
		t.Fatalf("cannot find any Servers by type %v", serverType)
	}
	return servers[0]
}

// getIPRuleRange returns if the given IP is included in the set of rules and which ip range it is included in
func getIPRule(rules, ip string) (bool, string) {
	for _, r := range strings.Split(rules, "\n")[1:] {
		if !strings.Contains(r, "src_ip") {
			continue
		}
		ipRange := r[7:strings.IndexAny(r, " ")]
		if exists, _ := util.IP4InRange(ip, ipRange); exists {
			return true, ipRange
		}
	}
	return false, ""
}
