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

-- last_deleted
CREATE TABLE IF NOT EXISTS last_deleted (
  table_name text NOT NULL PRIMARY KEY,
  last_updated timestamp with time zone NOT NULL DEFAULT now()
);

--
-- Name: on_delete_current_timestamp_last_updated(); Type: FUNCTION; Schema: public; Owner: traffic_ops
--
CREATE OR REPLACE FUNCTION public.on_delete_current_timestamp_last_updated()
    RETURNS trigger
    AS $$
BEGIN
  update last_deleted set last_updated = now() where table_name = TG_ARGV[0];
  RETURN NEW;
END;
$$
LANGUAGE plpgsql;

ALTER FUNCTION public.on_delete_current_timestamp_last_updated() OWNER TO traffic_ops;

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON api_capability
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('api_capability');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON asn
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('asn');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON cachegroup
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('cachegroup');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON cachegroup_fallbacks
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('cachegroup_fallbacks');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON cachegroup_localization_method
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('cachegroup_localization_method');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON cachegroup_parameter
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('cachegroup_parameter');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON capability
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('capability');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON cdn
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('cdn');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON coordinate
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('coordinate');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON deliveryservice
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('deliveryservice');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON deliveryservice_regex
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('deliveryservice_regex');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON deliveryservice_request
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('deliveryservice_request');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON deliveryservice_request_comment
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('deliveryservice_request_comment');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON deliveryservice_server
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('deliveryservice_server');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON deliveryservice_tmuser
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('deliveryservice_tmuser');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON division
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('division');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON federation
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('federation');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON federation_deliveryservice
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('federation_deliveryservice');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON federation_federation_resolver
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('federation_federation_resolver');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON federation_resolver
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('federation_resolver');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON federation_tmuser
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('federation_tmuser');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON hwinfo
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('hwinfo');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON job
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('job');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON job_agent
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('job_agent');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON job_status
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('job_status');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON log
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('log');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON origin
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('origin');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON parameter
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('parameter');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON phys_location
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('phys_location');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON profile
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('profile');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON profile_parameter
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('profile_parameter');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON regex
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('regex');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON region
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('region');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON role
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('role');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON role_capability
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('role_capability');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON server
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('server');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON servercheck
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('servercheck');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON snapshot
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('snapshot');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON staticdnsentry
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('staticdnsentry');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON stats_summary
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('stats_summary');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON status
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('status');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON steering_target
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('steering_target');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON tenant
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('tenant');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON tm_user
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('tm_user');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON to_extension
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('to_extension');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON topology
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('topology');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON topology_cachegroup
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('topology_cachegroup');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON topology_cachegroup_parents
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('topology_cachegroup_parents');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON type
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('type');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON user_role
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('user_role');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON server_capability
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('server_capability');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON server_server_capability
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('server_server_capability');

CREATE TRIGGER on_delete_current_timestamp
AFTER DELETE
ON deliveryservices_required_capability
FOR EACH ROW EXECUTE PROCEDURE on_delete_current_timestamp_last_updated('deliveryservices_required_capability');

create index api_capability_last_updated_idx on api_capability (last_updated DESC NULLS LAST);
create index asn_last_updated_idx on asn (last_updated DESC NULLS LAST);
create index cachegroup_last_updated_idx on cachegroup (last_updated DESC NULLS LAST);
create index cachegroup_parameter_last_updated_idx on cachegroup_parameter (last_updated DESC NULLS LAST);
create index capability_last_updated_idx on capability (last_updated DESC NULLS LAST);
create index cdn_last_updated_idx on cdn (last_updated DESC NULLS LAST);
create index coordinate_last_updated_idx on coordinate (last_updated DESC NULLS LAST);
create index deliveryservice_last_updated_idx on deliveryservice (last_updated DESC NULLS LAST);
create index deliveryservice_regex_last_updated_idx on deliveryservice_regex (last_updated DESC NULLS LAST);
create index deliveryservice_request_last_updated_idx on deliveryservice_request (last_updated DESC NULLS LAST);
create index deliveryservice_request_comment_last_updated_idx on deliveryservice_request_comment (last_updated DESC NULLS LAST);
create index deliveryservice_server_last_updated_idx on deliveryservice_server (last_updated DESC NULLS LAST);
create index deliveryservice_tmuser_last_updated_idx on deliveryservice_tmuser (last_updated DESC NULLS LAST);
create index division_last_updated_idx on division (last_updated DESC NULLS LAST);
create index federation_last_updated_idx on federation (last_updated DESC NULLS LAST);
create index federation_deliveryservice_last_updated_idx on federation_deliveryservice (last_updated DESC NULLS LAST);
create index federation_federation_resolver_last_updated_idx on federation_federation_resolver (last_updated DESC NULLS LAST);
create index federation_resolver_last_updated_idx on federation_resolver (last_updated DESC NULLS LAST);
create index federation_tmuser_last_updated_idx on federation_tmuser (last_updated DESC NULLS LAST);
create index hwinfo_last_updated_idx on hwinfo (last_updated DESC NULLS LAST);
create index job_last_updated_idx on job (last_updated DESC NULLS LAST);
create index job_agent_last_updated_idx on job_agent (last_updated DESC NULLS LAST);
create index job_status_last_updated_idx on job_status (last_updated DESC NULLS LAST);
create index log_last_updated_idx on log (last_updated DESC NULLS LAST);
create index origin_last_updated_idx on origin (last_updated DESC NULLS LAST);
create index parameter_last_updated_idx on parameter (last_updated DESC NULLS LAST);
create index pys_location_last_updated_idx on phys_location (last_updated DESC NULLS LAST);
create index profile_last_updated_idx on profile (last_updated DESC NULLS LAST);
create index profile_parameter_last_updated_idx on profile_parameter (last_updated DESC NULLS LAST);
create index regex_last_updated_idx on regex (last_updated DESC NULLS LAST);
create index region_last_updated_idx on region (last_updated DESC NULLS LAST);
create index role_last_updated_idx on role (last_updated DESC NULLS LAST);
create index role_capability_last_updated_idx on role_capability (last_updated DESC NULLS LAST);
create index server_last_updated_idx on server (last_updated DESC NULLS LAST);
create index servercheck_last_updated_idx on servercheck (last_updated DESC NULLS LAST);
create index snapshot_last_updated_idx on snapshot (last_updated DESC NULLS LAST);
create index staticdnsentry_last_updated_idx on staticdnsentry (last_updated DESC NULLS LAST);
create index status_last_updated_idx on status (last_updated DESC NULLS LAST);
create index steering_target_last_updated_idx on steering_target (last_updated DESC NULLS LAST);
create index tenant_last_updated_idx on tenant (last_updated DESC NULLS LAST);
create index tm_user_last_updated_idx on tm_user (last_updated DESC NULLS LAST);
create index to_extension_last_updated_idx on to_extension (last_updated DESC NULLS LAST);
create index topology_last_updated_idx on topology_cachegroup (last_updated DESC NULLS LAST);
create index topology_cachegroup_last_updated_idx on topology_cachegroup (last_updated DESC NULLS LAST);
create index topology_cachegroup_parents_last_updated_idx on topology_cachegroup_parents (last_updated DESC NULLS LAST);
create index type_last_updated_idx on type (last_updated DESC NULLS LAST);
create index user_role_last_updated_idx on user_role (last_updated DESC NULLS LAST);
create index server_capability_last_updated_idx on server_capability (last_updated DESC NULLS LAST);
create index server_server_capability_last_updated_idx on server_server_capability (last_updated DESC NULLS LAST);
create index deliveryservices_required_capability_last_updated_idx on deliveryservices_required_capability (last_updated DESC NULLS LAST);
