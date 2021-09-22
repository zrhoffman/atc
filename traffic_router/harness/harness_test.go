package main

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
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/apache/trafficcontrol/lib/go-tc"
	client "github.com/apache/trafficcontrol/traffic_ops/v4-client"

	"github.com/kelseyhightower/envconfig"
)

const (
	UserAgent = "Traffic Router Load Tests"
)

type TOConfig struct {
	TOURL      string `required:"true" envconfig:"TO_URL"`
	TOUser     string `required:"true" envconfig:"TO_USER"`
	TOPassword string `required:"true" envconfig:"TO_PASSWORD"`
	TOInsecure bool   `default:"true"  envconfig:"TO_INSECURE"`
	TOTimeout  int    `default:"30"    envconfig:"TO_TIMEOUT"`
}

type TRDetails struct {
	Hostname    string
	IPAddresses []string
	Port        int
	DSHost      string
}

type Benchmark struct {
	RequestsPerSecondThreshold int
	BenchmarkTime              int
	ThreadCount                int
	ClientIP                   *string
	PathCount                  int
	MaxPathLength              int
	DSType                     tc.Type
	TrafficRouters             []TRDetails
}

var (
	toConfig  TOConfig
	toSession *client.Session
	count     int
)

func getTOConfig() {
	err := envconfig.Process("", &toConfig)
	if err != nil {
		log.Fatalf("reading configuration from the environment: %s", err.Error())
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestMain(m *testing.M) {
	getTOConfig()
	ipv4Only := flag.Bool("4", false, "test IPv4 addresses only")
	ipv6Only := flag.Bool("6", false, "test IPv4 addresses only")
	cdnName := flag.String("cdn", "", "the name of a CDN to search for Delivery Services")
	deliveryServiceName := flag.String("ds", "", "the name (XMLID) of a Delivery Service to use for tests")
	trafficRouterName := flag.String("hostname", "", "the hostname of a Traffic Router to use")
	flag.Parse()

	var err error
	toSession, _, err = client.LoginWithAgent(toConfig.TOURL, toConfig.TOUser, toConfig.TOPassword, toConfig.TOInsecure, UserAgent, true, time.Second*time.Duration(toConfig.TOTimeout))
	if err != nil {
		log.Fatalf("logging into Traffic Ops server %s: %s", toConfig.TOURL, err.Error())
	}

	trafficRouters, err := getTrafficRouters(*trafficRouterName, tc.CDNName(*cdnName))
	if err != nil {
		log.Fatalf("could not get Traffic Routers: %s", err.Error())
	}

	trafficRouterDetails := []TRDetails{}
	ipAddresses := []string{}
	for _, trafficRouter := range trafficRouters {
		for _, serverInterface := range trafficRouter.Interfaces {
			if !serverInterface.Monitor {
				continue
			}
			ipv4, ipv6 := serverInterface.GetDefaultAddress()
			if ipv4 != "" && !*ipv6Only {
				ipAddresses = append(ipAddresses, ipv4)
			}
			if ipv6 != "" && !*ipv4Only {
				ipAddresses = append(ipAddresses, "["+ipv6+"]")
			}
		}
		if len(ipAddresses) < 1 {
			log.Printf("need at least 1 monitored service address on an interface of Traffic Router '%s' to use it for benchmarks, but %d such addresses were found", *trafficRouter.HostName, len(ipAddresses))
			continue
		}
		dsTypeName := tc.DSTypeHTTP
		httpDSes := getDSes(*trafficRouter.CDNID, dsTypeName, tc.DeliveryServiceName(*deliveryServiceName))
		if len(httpDSes) < 1 {
			log.Printf("at least 1 Delivery Service with type '%s' is required to run HTTP load tests on Traffic Router '%s', but %d were found", dsTypeName, *trafficRouter.HostName, len(httpDSes))
		}
		dsURL, err := url.Parse(httpDSes[0].ExampleURLs[0])
		if err != nil {
			log.Fatalf("parsing Delivery Service URL %s: %s", dsURL, err.Error())
		}
		trafficRouterDetails = append(trafficRouterDetails, TRDetails{
			Hostname:    *trafficRouter.HostName,
			IPAddresses: ipAddresses,
			Port:        *trafficRouter.TCPPort,
			DSHost:      dsURL.Host,
		})
	}
	if len(trafficRouterDetails) < 1 {
		log.Fatalf("no Traffic Router with at least 1 HTTP Delivery Service and at least 1 monitored service address was found")
	}
	benchmark := Benchmark{
		RequestsPerSecondThreshold: 2000,
		//BenchmarkTime:              300,
		BenchmarkTime:  10,
		ThreadCount:    12,
		ClientIP:       nil,
		PathCount:      10000,
		MaxPathLength:  100,
		TrafficRouters: trafficRouterDetails,
	}

	trafficRouterIndex := 0
	trafficRouter := benchmark.TrafficRouters[trafficRouterIndex]
	ipAddressIndex := 0
	ipAddress := trafficRouter.IPAddresses[ipAddressIndex]
	trafficRouterURL := fmt.Sprintf("http://%s:%d/", ipAddress, trafficRouter.Port)
	//trafficRouterURL = "http://172.17.0.1:3080/" // TODO: remove this

	redirects, failures := 0, 0
	redirectsChannels := make([]chan int, benchmark.ThreadCount)
	failuresChannels := make([]chan int, benchmark.ThreadCount)
	for threadIndex := 0; threadIndex < benchmark.ThreadCount; threadIndex++ {
		redirectsChannels[threadIndex] = make(chan int)
		failuresChannels[threadIndex] = make(chan int)
		go benchmark.Run(redirectsChannels[threadIndex], failuresChannels[threadIndex], trafficRouterIndex, trafficRouterURL, ipAddressIndex)
	}

	for threadIndex := 0; threadIndex < benchmark.ThreadCount; threadIndex++ {
		redirects += <-redirectsChannels[threadIndex]
		failures += <-failuresChannels[threadIndex]
	}
	fmt.Printf("%d redirects and %d failures\n", redirects, failures)
}

func (b Benchmark) Run(redirectsChannel chan int, failuresChannel chan int, trafficRouterIndex int, trafficRouterURL string, ipAddressIndex int) {
	paths := generatePaths(b.PathCount, b.MaxPathLength)
	stopTime := time.Now().Add(time.Duration(b.BenchmarkTime) * time.Second)
	redirects, failures := 0, 0
	var req *http.Request
	var resp *http.Response
	var err error
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for time.Now().Before(stopTime) {
		requestURL := trafficRouterURL + paths[rand.Intn(len(paths))]
		if req, err = http.NewRequest("GET", requestURL, nil); err != nil {
			log.Fatalf("creating GET request to Traffic Router '%s' (IP address %s): %s",
				b.TrafficRouters[trafficRouterIndex].Hostname, b.TrafficRouters[trafficRouterIndex].IPAddresses[ipAddressIndex], err.Error())
		}
		req.Host = b.TrafficRouters[trafficRouterIndex].DSHost
		resp, err = httpClient.Do(req)
		if err == nil && resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
			redirects++
		} else {
			failures++
		}
	}
	redirectsChannel <- redirects
	failuresChannel <- failures
}

func generatePaths(pathCount, maxPathLength int) []string {
	const alphabetSize = 26 + 26 + 10
	alphabet := make([]rune, alphabetSize)
	index := 0
	for char := 'A'; char <= 'Z'; char++ {
		alphabet[index] = char
		index++
	}
	for char := 'a'; char <= 'z'; char++ {
		alphabet[index] = char
		index++
	}
	for char := '0'; char <= '9'; char++ {
		alphabet[index] = char
		index++
	}
	paths := make([]string, pathCount)
	for index = 0; index < pathCount; index++ {
		pathLength := rand.Intn(maxPathLength)
		url := make([]rune, pathLength)
		for runeIndex := 0; runeIndex < pathLength; runeIndex++ {
			url[runeIndex] = alphabet[rand.Intn(alphabetSize)]
		}
		paths[index] = string(url)
	}
	return paths
}

func BenchmarkHttpDSes(b *testing.B) {
	fmt.Printf("count: %d\n", count)
	count++
	time.Sleep(time.Second * 3)
}

func getTrafficRouters(trafficRouterName string, cdnName tc.CDNName) ([]tc.ServerV40, error) {
	requestOptions := client.RequestOptions{QueryParameters: url.Values{
		"type":   {tc.RouterTypeName},
		"status": {tc.CacheStatusOnline.String()},
	}}
	if trafficRouterName != "" {
		requestOptions.QueryParameters.Set("hostName", trafficRouterName)
	}
	if cdnName != "" {
		cdnRequestOptions := client.RequestOptions{QueryParameters: url.Values{
			"name": {string(cdnName)},
		}}
		cdnResponse, _, err := toSession.GetCDNs(cdnRequestOptions)
		if err != nil {
			return nil, fmt.Errorf("requesting a CDN named '%s': %s", cdnName, err.Error())
		}
		cdns := cdnResponse.Response
		if len(cdns) != 1 {
			return nil, fmt.Errorf("did not find exactly 1 CDN with name '%s'", cdnName)
		}
		requestOptions.QueryParameters.Set("cdn", string(cdnName))
	}
	response, _, err := toSession.GetServers(requestOptions)
	if err != nil {
		return nil, fmt.Errorf("requesting %s-status Traffic Routers: %s", requestOptions.QueryParameters["status"], err.Error())
	}
	trafficRouters := response.Response
	if len(trafficRouters) < 1 {
		return trafficRouters, fmt.Errorf("no Traffic Routers were found with these criteria: %v", requestOptions.QueryParameters)
	}
	return trafficRouters, nil
}

func getDSes(cdnId int, dsTypeName tc.DSType, dsName tc.DeliveryServiceName) []tc.DeliveryServiceV40 {
	requestOptions := client.RequestOptions{QueryParameters: url.Values{"name": {dsTypeName.String()}}}
	var dsType tc.Type
	{
		response, _, err := toSession.GetTypes(requestOptions)
		if err != nil {
			log.Fatalf("getting type %s: %s", requestOptions.QueryParameters["name"], err.Error())
		}
		types := response.Response
		if len(types) != 1 {
			log.Fatalf("did not find exactly 1 type with name '%s'", requestOptions.QueryParameters["name"])
		}
		dsType = types[0]
	}

	requestOptions = client.RequestOptions{QueryParameters: url.Values{
		"cdn":    {strconv.Itoa(cdnId)},
		"type":   {strconv.Itoa(dsType.ID)},
		"status": {tc.CacheStatusOnline.String()},
	}}
	if dsName != "" {
		requestOptions.QueryParameters.Set("xmlId", dsName.String())
	}
	response, _, err := toSession.GetDeliveryServices(requestOptions)
	if err != nil {
		log.Fatalf("getting Delivery Services with type '%s' (type ID %d): %s", dsType.Name, dsType.ID, err.Error())
	}
	httpDSes := response.Response
	return httpDSes
}
