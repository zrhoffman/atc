package topology

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
	"database/sql"
	"encoding/json"
	"errors"
	fmt "fmt"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"net/http"

	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/api"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/dbhelpers"
)

func QueueUpdateHandler(w http.ResponseWriter, r *http.Request) {
	inf, userErr, sysErr, errCode := api.NewInfo(r, []string{"name"}, []string{})
	if userErr != nil || sysErr != nil {
		api.HandleErr(w, r, inf.Tx.Tx, errCode, userErr, sysErr)
		return
	}
	defer inf.Close()
	reqObj := tc.TopologiesQueueUpdateRequest{}
	if err := json.NewDecoder(r.Body).Decode(&reqObj); err != nil {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusBadRequest, errors.New("malformed JSON: "+err.Error()), nil)
		return
	}
	if reqObj.Action != "queue" && reqObj.Action != "dequeue" {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusBadRequest, errors.New("action must be 'queue' or 'dequeue'"), nil)
		return
	}
	topologyName := tc.TopologyName(inf.Params["name"])
	if err := queueUpdates(inf.Tx.Tx, inf.Params["name"], reqObj.Action == "queue"); err != nil {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusInternalServerError, nil, errors.New("Topology queueing updates: "+err.Error()))
		return
	}

	topologyExists, err := dbhelpers.TopologyExists(inf.Tx.Tx, topologyName)
	if err != nil {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusInternalServerError, nil, fmt.Errorf("checking whether topology %s exists: %s", topologyName, err))
		return
	} else if !topologyExists {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusInternalServerError, fmt.Errorf("no topology exists by the name of %s", topologyName), nil)
		return
	}

	message := fmt.Sprintf("TOPOLOGY: %s, ACTION: Topology server updates %sd", topologyName, reqObj.Action)
	api.CreateChangeLogRawTx(api.ApiChange, message, inf.User, inf.Tx.Tx)
	api.WriteResp(w, r, tc.TopologiesQueueUpdateResponse{Action: reqObj.Action, Topology: topologyName})
}

func queueUpdates(tx *sql.Tx, topologyName string, queue bool) error {
	query := `
UPDATE server s
SET upd_pending = $1
FROM cachegroup c, topology_cachegroup tc
WHERE s.cachegroup = c.id
AND c."name" = tc.cachegroup
AND tc.topology = $2
`
	var err error
	if _, err = tx.Exec(query, queue, topologyName); err != nil {
		err = fmt.Errorf("queueing updates: %s", err)
	}
	return err
}
