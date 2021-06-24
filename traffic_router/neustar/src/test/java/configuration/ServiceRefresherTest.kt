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

import com.comcast.cdn.traffic_control.traffic_router.neustar.NeustarGeolocationService

class ServiceRefresherTest {
    @Mock
    var neustarDatabaseUpdater: NeustarDatabaseUpdater? = null

    @Mock
    var neustarGeolocationService: NeustarGeolocationService? = null

    @InjectMocks
    var serviceRefresher: ServiceRefresher? = null

    @Before
    fun before() {
        initMocks(this)
    }

    @Test
    fun itSwallowsExceptions() {
        `when`(neustarDatabaseUpdater.update()).thenThrow(RuntimeException("Boom!"))
        serviceRefresher.run()
        verify(neustarDatabaseUpdater).update()
    }
}