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

DO $$
DECLARE r record;
BEGIN
  FOR r IN (SELECT indexname FROM pg_indexes WHERE tablename = 'server' AND indexname LIKE '%primary%')
  LOOP
    EXECUTE 'ALTER TABLE server DROP CONSTRAINT IF EXISTS '|| quote_ident(r.indexname) || ';';
  END LOOP;
  EXECUTE 'ALTER TABLE ONLY server ADD CONSTRAINT '|| quote_ident(r.indexname) || ' PRIMARY KEY (id);';
END
$$ LANGUAGE plpgsql;
