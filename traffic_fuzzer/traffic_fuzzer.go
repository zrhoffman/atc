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
	"context"
	"encoding/json"
	"fmt"
	"github.com/apache/trafficcontrol/lib/go-tc"
	client "github.com/apache/trafficcontrol/traffic_ops/v3-client"
	"github.com/ffuf/ffuf/pkg/ffuf"
	"github.com/ffuf/ffuf/pkg/filter"
	"github.com/ffuf/ffuf/pkg/input"
	"github.com/ffuf/ffuf/pkg/output"
	"github.com/ffuf/ffuf/pkg/runner"
	"io/ioutil"
	"net/url"
	"os"
	"time"
)


func main() {
	_, cookies := logIn()
}

func logIn() (*client.Session, []string) {
	toUrl := os.Getenv("TO_URL")
	toUser := os.Getenv("TO_USER")
	toPassword := os.Getenv("TO_PASSWORD")

	toSession, _, err := client.LoginWithAgent(toUrl, toUser, toPassword, true, "Traffic Fuzzer", false, 10*time.Second)
	if err != nil {
		fmt.Printf("Logging into Traffic Ops: %s", err.Error())
		os.Exit(1)
	}

	cookieURL, err := url.Parse(toUrl)
	if err != nil {
		fmt.Printf("Parsing Traffic Ops host: %s", err.Error())
		os.Exit(1)
	}
	cookies := toSession.Client.Jar.Cookies(cookieURL)
	cookieStrings := make([]string, len(cookies))
	for index, cookie := range cookies {
		cookieStrings[index] = cookie.String()
	}
	return toSession, cookieStrings
}
