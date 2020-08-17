<!--
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
-->

# ciab-image JavaScript action

This action builds the CDN-in-a-Box images corresponding to a single Traffic Control component.

## Inputs
None

## Environment variables:
- RPM_PATHS: A comma-separated list of RPM paths to pass to `make`.
- CIAB_IMAGES: A comma-separated list of docker-compose services to build.
- ATC_COMPONENT (optional): The name of the ATC component

## Outputs
### `exit-code`

0 on success, non-zero otherwise

## Example usage
```yaml
uses: actions/ciab-image@master
```
