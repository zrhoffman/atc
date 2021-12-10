# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from typing import Final

ENV_GITHUB_REPOSITORY: Final[str] = 'GITHUB_REPOSITORY'
ENV_GITHUB_TOKEN: Final[str] = 'GITHUB_TOKEN'

GH_TIMELINE_EVENT_TYPE_CROSS_REFERENCE: Final[str] = 'cross-referenced'

TRIAGE_USER_MINIMUM_COMMITS: Final[int] = 2
SINCE_DAYS_AGO: Final[int] = 31
ASF_YAML_FILE: Final[str] = '.asf.yaml'
APACHE_LICENSE_YAML: Final[str] = 'apache_license.yml'
