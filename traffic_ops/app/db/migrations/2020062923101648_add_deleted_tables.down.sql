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

DROP TABLE IF EXISTS last_deleted;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on api_capability;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on asn;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on cachegroup;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on cachegroup_fallbacks;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on cachegroup_localization_method;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on cachegroup_parameter;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on capability;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on cdn;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on coordinate;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on deliveryservice;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on deliveryservice_regex;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on deliveryservice_request;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on deliveryservice_request_comment;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on deliveryservice_server;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on deliveryservice_tmuser;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on division;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on federation;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on federation_deliveryservice;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on federation_federation_resolver;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on federation_resolver;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on federation_tmuser;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on hwinfo;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on job;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on job_agent;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on job_status;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on log;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on origin;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on parameter;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on phys_location;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on profile;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on profile_parameter;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on regex;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on region;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on role;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on role_capability;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on server;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on servercheck;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on snapshot;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on staticdnsentry;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on stats_summary;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on status;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on steering_target;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on tenant;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on tm_user;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on topology;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on topology_cachegroup;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on topology_cachegroup_parents;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on to_extension;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on type;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on user_role;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on server_capability;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on server_server_capability;
DROP TRIGGER IF EXISTS on_delete_current_timestamp on deliveryservices_required_capability;

DROP INDEX IF EXISTS api_capability_last_updated_idx;
DROP INDEX IF EXISTS asn_last_updated_idx;
DROP INDEX IF EXISTS cachegroup_last_updated_idx;
DROP INDEX IF EXISTS cachegroup_parameter_last_updated_idx;
DROP INDEX IF EXISTS capability_last_updated_idx;
DROP INDEX IF EXISTS cdn_last_updated_idx;
DROP INDEX IF EXISTS coordinate_last_updated_idx;
DROP INDEX IF EXISTS deliveryservice_last_updated_idx;
DROP INDEX IF EXISTS deliveryservice_regex_last_updated_idx;
DROP INDEX IF EXISTS deliveryservice_request_last_updated_idx;
DROP INDEX IF EXISTS deliveryservice_request_comment_last_updated_idx;
DROP INDEX IF EXISTS deliveryservice_server_last_updated_idx;
DROP INDEX IF EXISTS deliveryservice_tmuser_last_updated_idx;
DROP INDEX IF EXISTS division_last_updated_idx;
DROP INDEX IF EXISTS federation_last_updated_idx;
DROP INDEX IF EXISTS federation_deliveryservice_last_updated_idx;
DROP INDEX IF EXISTS federation_federation_resolver_last_updated_idx;
DROP INDEX IF EXISTS federation_resolver_last_updated_idx;
DROP INDEX IF EXISTS federation_tmuser_last_updated_idx;
DROP INDEX IF EXISTS hwinfo_last_updated_idx;
DROP INDEX IF EXISTS job_last_updated_idx;
DROP INDEX IF EXISTS job_agent_last_updated_idx;
DROP INDEX IF EXISTS job_status_last_updated_idx;
DROP INDEX IF EXISTS log_last_updated_idx;
DROP INDEX IF EXISTS origin_last_updated_idx;
DROP INDEX IF EXISTS parameter_last_updated_idx;
DROP INDEX IF EXISTS pys_location_last_updated_idx;
DROP INDEX IF EXISTS profile_last_updated_idx;
DROP INDEX IF EXISTS profile_parameter_last_updated_idx;
DROP INDEX IF EXISTS regex_last_updated_idx;
DROP INDEX IF EXISTS region_last_updated_idx;
DROP INDEX IF EXISTS role_last_updated_idx;
DROP INDEX IF EXISTS role_capability_last_updated_idx;
DROP INDEX IF EXISTS server_last_updated_idx;
DROP INDEX IF EXISTS servercheck_last_updated_idx;
DROP INDEX IF EXISTS snapshot_last_updated_idx;
DROP INDEX IF EXISTS staticdnsentry_last_updated_idx;
DROP INDEX IF EXISTS status_last_updated_idx;
DROP INDEX IF EXISTS steering_target_last_updated_idx;
DROP INDEX IF EXISTS tenant_last_updated_idx;
DROP INDEX IF EXISTS tm_user_last_updated_idx;
DROP INDEX IF EXISTS to_extension_last_updated_idx;
DROP INDEX IF EXISTS topology_last_updated_idx;
DROP INDEX IF EXISTS topology_cachegroup_last_updated_idx;
DROP INDEX IF EXISTS topology_cachegroup_parents_last_updated_idx;
DROP INDEX IF EXISTS type_last_updated_idx;
DROP INDEX IF EXISTS user_role_last_updated_idx;
DROP INDEX IF EXISTS server_capability_last_updated_idx;
DROP INDEX IF EXISTS server_server_capability_last_updated_idx;
DROP INDEX IF EXISTS deliveryservices_required_capability_last_updated_idx;
