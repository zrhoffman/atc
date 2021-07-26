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

DROP TRIGGER IF EXISTS before_update_ip_address_trigger ON ip_address;
DROP TRIGGER IF EXISTS before_create_ip_address_trigger ON ip_address;

DROP FUNCTION IF EXISTS before_ip_address_table();

CREATE OR REPLACE FUNCTION before_ip_address_table()
    RETURNS TRIGGER
AS
$$
DECLARE
    server_count   BIGINT;
    server_id      BIGINT;
    server_profile BIGINT;
BEGIN
    WITH server_ips AS (
        SELECT s.id as sid, ip.interface, i.name, ip.address, s.profile, ip.server
        FROM server s
                 JOIN interface i
                     on i.server = s.ID
                 JOIN ip_address ip
                     on ip.Server = s.ID and ip.interface = i.name
        WHERE i.monitor = true
    )
    SELECT count(sip.sid), sip.sid, sip.profile
    INTO server_count, server_id, server_profile
    FROM server_ips sip
             JOIN server_ips sip2 on sip.sid <> sip2.sid
    WHERE (sip.server = NEW.server AND sip.address = NEW.address AND sip.interface = NEW.interface)
      AND sip2.address = sip.address
      AND sip2.profile = sip.profile
    GROUP BY sip.sid, sip.profile;

    IF server_count > 0 THEN
        RAISE EXCEPTION 'ip_address is not unique across the server [id:%] profile [id:%], [%] conflicts',
            server_id,
            server_profile,
            server_count;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE PLPGSQL;

CREATE TRIGGER before_create_ip_address_trigger
    BEFORE INSERT
    ON ip_address
    FOR EACH ROW
EXECUTE PROCEDURE before_ip_address_table();

CREATE TRIGGER before_update_ip_address_trigger
    BEFORE UPDATE
    ON ip_address
    FOR EACH ROW
    WHEN (NEW.address <> OLD.address)
EXECUTE PROCEDURE before_ip_address_table();
