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

DROP TRIGGER IF EXISTS before_update_server_trigger ON server;
DROP TRIGGER IF EXISTS before_create_server_trigger ON server;
DROP TRIGGER IF EXISTS before_update_ip_address_trigger ON ip_address;
DROP TRIGGER IF EXISTS before_create_ip_address_trigger ON ip_address;

DROP FUNCTION IF EXISTS before_server_table();
DROP FUNCTION IF EXISTS before_ip_address_table();
