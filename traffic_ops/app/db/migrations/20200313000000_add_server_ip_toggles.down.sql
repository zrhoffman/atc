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

ALTER TABLE server DROP COLUMN ip_address_is_service;
ALTER TABLE server DROP COLUMN ip6_address_is_service;
ALTER TABLE server ALTER COLUMN ip_address SET NOT NULL;
ALTER TABLE server ALTER COLUMN ip_netmask SET NOT NULL;
ALTER TABLE server ALTER COLUMN ip_gateway SET NOT NULL;
ALTER TABLE server DROP CONSTRAINT need_at_least_one_ip;
ALTER TABLE server DROP CONSTRAINT need_gateway_if_ip;
ALTER TABLE server DROP CONSTRAINT need_netmask_if_ip;
