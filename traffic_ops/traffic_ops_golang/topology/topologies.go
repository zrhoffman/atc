package topology

import (
	"fmt"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/lib/go-tc/tovalidate"
	"github.com/apache/trafficcontrol/lib/go-util"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/api"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/cachegroup"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/lib/pq"
)

type TOTopology struct {
	api.APIInfoImpl `json:"-"`
	tc.Topology
}

func (topology *TOTopology) SetLastUpdated(time tc.TimeNoMod) { topology.LastUpdated = &time }

func (topology TOTopology) GetKeyFieldsInfo() []api.KeyFieldInfo {
	return []api.KeyFieldInfo{{"name", api.GetStringKey}}
}

func (topology *TOTopology) GetType() string {
	return "topology"
}

func (topology *TOTopology) Validate() error {
	nameRule := validation.NewStringRule(tovalidate.IsAlphanumericUnderscoreDash, "must consist of only alphanumeric, dash, or underscore characters.")
	rules := validation.Errors{}
	rules["name"] = validation.Validate(topology.Name, validation.Required, nameRule)

	nodeCount := len(topology.Nodes)
	rules["length"] = validation.Validate(nodeCount, validation.Min(1))
	cacheGroups := make([]*tc.CacheGroupNullable, nodeCount)
	var err error
	for index := 0; index < nodeCount; index++ {
		node := &topology.Nodes[index]
		rules[fmt.Sprintf("node %v parents size", index)] = validation.Validate(node.Parents, validation.Length(0, 2))
		rules[fmt.Sprintf("node %v duplicate parents", index)] = checkForDuplicateParents(&topology.Nodes, index)
		if cacheGroups[index], err = cachegroup.GetCacheGroupByName(node.Cachegroup, &topology.APIInfoImpl); err != nil {
			rules[fmt.Sprintf("node %v parents size", index)] = fmt.Errorf("error getting cachegroup %v: %v", node.Cachegroup, err.Error())
		}
	}
	rules["duplicate cachegroup name"] = checkUniqueCacheGroupNames(topology.Nodes)

	for index := 0; index < nodeCount; index++ {
		rules["parents edge type"] = checkForEdgeParents(&topology.Nodes, &cacheGroups, index)
	}
	errs := tovalidate.ToErrors(rules)
	return util.JoinErrs(errs)
}

// Implementation of the Identifier, Validator interface functions
func (topology TOTopology) GetKeys() (map[string]interface{}, bool) {
	return map[string]interface{}{"name": topology.Name}, true
}

func (topology *TOTopology) SetKeys(keys map[string]interface{}) {
	topology.Name, _ = keys["name"].(string)
}

func (topology *TOTopology) GetAuditName() string {
	return topology.Name
}

func (topology *TOTopology) Create() (error, error, int) {
	tx := topology.APIInfo().Tx.Tx
	err := tx.QueryRow(insertQuery(), topology.Name, topology.Description).Scan(&topology.Name, &topology.Description, &topology.LastUpdated)
	if err != nil {
		userErr, sysErr, errCode := api.ParseDBError(err)
		return userErr, sysErr, errCode
	}

	nodeCount := len(topology.Nodes)
	cachegroups := make([]string, nodeCount)
	for index := 0; index < nodeCount; index++ {
		node := &topology.Nodes[index]
		cachegroups[index] = node.Cachegroup
	}
	rows, err := tx.Query(nodeInsertQuery(), topology.Name, pq.Array(cachegroups))
	if err != nil {
		userErr, sysErr, errCode := api.ParseDBError(err)
		return userErr, sysErr, errCode
	}
	for index := 0; index < nodeCount; index++ {
		node := &topology.Nodes[index]
		rows.Next()
		err = rows.Scan(&node.Id, &topology.Name, &node.Cachegroup)
		if err != nil {
			userErr, sysErr, errCode := api.ParseDBError(err)
			return userErr, sysErr, errCode
		}
	}
	err = rows.Close()
	if err != nil {
		userErr, sysErr, errCode := api.ParseDBError(err)
		return userErr, sysErr, errCode
	}

	children := []int{}
	parents := []int{}
	ranks := []int{}
	for index := 0; index < nodeCount; index++ {
		node := &topology.Nodes[index]
		for rank := 1; rank <= len(node.Parents); rank++ {
			parent := &topology.Nodes[node.Parents[rank-1]]
			children = append(children, node.Id)
			parents = append(parents, parent.Id)
			ranks = append(ranks, rank)
		}
	}
	rows, err = tx.Query(nodeParentInsertQuery(), pq.Array(children), pq.Array(parents), pq.Array(ranks))
	if err != nil {
		userErr, sysErr, errCode := api.ParseDBError(err)
		return userErr, sysErr, errCode
	}
	for index := 0; index < nodeCount; index++ {
		node := &topology.Nodes[index]
		for rank := 1; rank <= len(node.Parents); rank++ {
			rows.Next()
			parent := &topology.Nodes[node.Parents[rank-1]]
			err = rows.Scan(&node.Id, &parent.Id, &rank)
			if err != nil {
				userErr, sysErr, errCode := api.ParseDBError(err)
				return userErr, sysErr, errCode
			}
		}
	}
	err = rows.Close()
	if err != nil {
		userErr, sysErr, errCode := api.ParseDBError(err)
		return userErr, sysErr, errCode
	}

	return nil, nil, 0
}

func insertQuery() string {
	query := `
INSERT INTO topology (name, description)
VALUES ($1, $2)
RETURNING name, description, last_updated
`
	return query
}

func nodeInsertQuery() string {
	query := `
INSERT INTO topology_cachegroup (topology, cachegroup)
VALUES ($1, unnest($2::text[]))
RETURNING id, topology, cachegroup
`
	return query
}

func nodeParentInsertQuery() string {
	query := `
INSERT INTO topology_cachegroup_parents (child, parent, rank)
VALUES (unnest($1::int[]), unnest($2::int[]), unnest($3::int[]))
RETURNING child, parent, rank
`
	return query
}
