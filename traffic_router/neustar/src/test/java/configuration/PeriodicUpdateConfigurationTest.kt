/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package configuration

import com.comcast.cdn.traffic_control.traffic_router.neustar.configuration.NeustarConfiguration

@RunWith(SpringJUnit4ClassRunner::class)
@ContextConfiguration(
    classes = [NeustarConfiguration::class, PeriodicUpdateConfigurationTest.TestConfiguration::class],
    loader = AnnotationConfigContextLoader::class
)
class PeriodicUpdateConfigurationTest constructor() {
    @Autowired
    var neustarDatabaseDirectory: File? = null

    @Autowired
    var neustarOldDatabaseDirectory: File? = null
    @Test
    fun itUsesCorrectDirectoriesForDataDownload() {
        assertThat(neustarDatabaseDirectory.getAbsolutePath(), equalTo("/opt/traffic_router/db/neustar"))
        assertThat(neustarOldDatabaseDirectory.getAbsolutePath(), equalTo("/opt/traffic_router/db/neustar/old"))
    }

    @Configuration
    internal class TestConfiguration constructor() {
        @Bean
        fun databasesDir(): Path? {
            return Paths.get("/opt/traffic_router/db")
        }
    }
}