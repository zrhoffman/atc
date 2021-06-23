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
package geolocation

import com.comcast.cdn.traffic_control.traffic_router.neustar.NeustarGeolocationService

@RunWith(PowerMockRunner::class)
@PrepareForTest([NeustarGeolocationService::class, GPDatabaseReader::class, Reader::class])
class NeustarGeolocationServiceTest {
    @Mock
    var neustarDatabaseDirectory: File? = null

    @InjectMocks
    var service: NeustarGeolocationService? = NeustarGeolocationService()
    @Before
    @Throws(Exception::class)
    fun before() {
        // This prevents extraneous output about 'WARN No appenders could be found....'
        LogManager.getRootLogger().addAppender(mock(Appender::class.java))
        initMocks(this)
        service.init()
    }

    @Test
    @Throws(Exception::class)
    fun itNoLongerAllowsVerifyDatabase() {
        try {
            service.verifyDatabase(neustarDatabaseDirectory)
            fail("Should have thrown RuntimeException when calling verifyDatabase")
        } catch (e: RuntimeException) {
            assertThat(
                e.getMessage(),
                equalTo(
                    "verifyDatabase is no longer allowed, " + NeustarDatabaseUpdater::class.java.getSimpleName()
                        .toString() + " is used for verification instead"
                )
            )
        }
    }

    @Test
    @Throws(Exception::class)
    fun itReturnsNullWhenDatabaseNotLoaded() {
        assertThat(service.isInitialized(), equalTo(false))
        assertThat(service.location("192.168.99.100"), nullValue())
    }

    @Test
    @Throws(Exception::class)
    fun itReturnsNullWhenDatabaseDoesNotExist() {
        `when`(neustarDatabaseDirectory.getAbsolutePath()).thenReturn("/path/to/file/")
        assertThat(service.isInitialized(), equalTo(false))
        assertThat(service.location("192.168.99.100"), nullValue())
        service.reloadDatabase()
        assertThat(service.isInitialized(), equalTo(false))
        assertThat(service.location("192.168.99.100"), nullValue())
    }

    @Test
    @PrepareForTest([GPDatabaseReader.Builder::class, NeustarGeolocationService::class])
    @Throws(Exception::class)
    fun itReturnsALocationWhenTheDatabaseIsLoaded() {
        `when`(neustarDatabaseDirectory.exists()).thenReturn(true)
        `when`(neustarDatabaseDirectory.list()).thenReturn(arrayOf<String?>("foo.gpdb"))
        val geoPointResponse: GeoPointResponse = mock(GeoPointResponse::class.java)
        `when`(geoPointResponse.getCity()).thenReturn("Springfield")
        `when`(geoPointResponse.getLatitude()).thenReturn(40.0)
        `when`(geoPointResponse.getLongitude()).thenReturn(-105.0)
        `when`(geoPointResponse.getCountry()).thenReturn("United States")
        `when`(geoPointResponse.getCountryCode()).thenReturn("100")
        val gpDatabaseReader: GPDatabaseReader = mock(GPDatabaseReader::class.java)
        `when`(gpDatabaseReader.ipInfo(InetAddress.getByName("192.168.99.100"))).thenReturn(geoPointResponse)
        val builder: GPDatabaseReader.Builder = mock(GPDatabaseReader.Builder::class.java)
        `when`(builder.build()).thenReturn(gpDatabaseReader)
        whenNew(GPDatabaseReader.Builder::class.java).withArguments(neustarDatabaseDirectory).thenReturn(builder)
        service.reloadDatabase()
        assertThat(service.isInitialized(), equalTo(true))
        val geolocation: Geolocation = service.location("192.168.99.100")
        assertThat(geolocation.getCity(), equalTo("Springfield"))
        assertThat(geolocation.getLatitude(), equalTo(40.0))
        assertThat(geolocation.getLongitude(), equalTo(-105.0))
        assertThat(geolocation.getCountryName(), equalTo("United States"))
        assertThat(geolocation.getCountryCode(), equalTo("100"))
        assertThat(service.location("192.168.99.100"), notNullValue())
    }

    @After
    fun after() {
        service.destroy()
    }
}