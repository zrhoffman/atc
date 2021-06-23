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
package data

import com.comcast.cdn.traffic_control.traffic_router.neustar.data.HttpClient

@RunWith(PowerMockRunner::class)
@PowerMockIgnore("javax.net.ssl.*")
@PrepareForTest([NeustarDatabaseUpdater::class, Files::class])
class NeustarDatabaseUpdaterTest constructor() {
    @Mock
    var neustarDatabaseDirectory: File? = null

    @Mock
    var neustarOldDatabaseDirectory: File? = null

    @Mock
    var tarExtractor: TarExtractor? = null

    @Mock
    var filesMover: FilesMover? = null

    @InjectMocks
    var neustarDatabaseUpdater: NeustarDatabaseUpdater? = null
    private var mockTmpDir: File? = null
    @Before
    @Throws(Exception::class)
    fun before() {
        initMocks(this)
        `when`(neustarOldDatabaseDirectory.isDirectory()).thenReturn(true)
        `when`(neustarOldDatabaseDirectory.lastModified()).thenReturn(1425236082000L)
        mockTmpDir = mock(File::class.java)
        `when`(mockTmpDir.getName()).thenReturn("123-abc-tmp")
        `when`(mockTmpDir.getParentFile()).thenReturn(neustarDatabaseDirectory)
        `when`(neustarDatabaseDirectory.listFiles()).thenReturn(arrayOf<File?>(neustarOldDatabaseDirectory, mockTmpDir))
        val path: Path? = mock(Path::class.java)
        `when`(path.toFile()).thenReturn(mockTmpDir)
        mockStatic(Files::class.java)
        `when`(Files.createTempDirectory(any(Path::class.java), eq("neustar-"))).thenReturn(path)
        `when`(tarExtractor.extractTo(eq(mockTmpDir), any(GZIPInputStream::class.java))).thenReturn(true)
    }

    @Test
    @PrepareForTest([NeustarDatabaseUpdater::class, GZIPInputStream::class, GPDatabaseReader.Builder::class])
    @Throws(
        Exception::class
    )
    fun itRetrievesRemoteFileContents() {
        val statusLine: StatusLine? = mock(StatusLine::class.java)
        `when`(statusLine.getStatusCode()).thenReturn(200)
        val remoteInputStream: InputStream? = mock(InputStream::class.java)
        val httpEntity: HttpEntity? = mock(HttpEntity::class.java)
        `when`(httpEntity.getContent()).thenReturn(remoteInputStream)
        val response: CloseableHttpResponse? = mock(CloseableHttpResponse::class.java)
        `when`(response.getStatusLine()).thenReturn(statusLine)
        `when`(response.getEntity()).thenReturn(httpEntity)
        val httpClient: HttpClient? = mock(HttpClient::class.java)
        `when`(httpClient.execute(any(HttpGet::class.java))).thenReturn(response)
        val gzipInputStream: GZIPInputStream? = mock(GZIPInputStream::class.java)
        whenNew(GZIPInputStream::class.java).withArguments(remoteInputStream).thenReturn(gzipInputStream)
        whenNew(GPDatabaseReader.Builder::class.java).withArguments(any(File::class.java)).thenReturn(
            mock(
                GPDatabaseReader.Builder::class.java
            )
        )
        neustarDatabaseUpdater.setHttpClient(httpClient)
        neustarDatabaseUpdater.setNeustarDataUrl("http://example.com/neustardata.tgz")
        neustarDatabaseUpdater.setNeustarPollingTimeout(100)
        `when`(
            filesMover.updateCurrent(
                eq(neustarDatabaseDirectory),
                any(File::class.java),
                eq(neustarOldDatabaseDirectory)
            )
        ).thenReturn(true)
        assertThat(neustarDatabaseUpdater.update(), equalTo(true))
        verify(httpClient).close()
        verify(response).close()
    }

    @Test
    fun itDeterminesLatestBuildDate() {
        assertThat(neustarDatabaseUpdater.getDatabaseBuildDate(), nullValue())
        val file: File? = mock(File::class.java)
        `when`(file.lastModified()).thenReturn(1425236082000L)
        `when`(neustarDatabaseDirectory.listFiles()).thenReturn(arrayOf<File?>(file))
        assertThat(neustarDatabaseUpdater.getDatabaseBuildDate(), equalTo(Date(1425236082000L)))
    }

    companion object {
        @BeforeClass
        fun beforeClass() {
            LogManager.getRootLogger().addAppender(ConsoleAppender(PatternLayout("%d %-5p [%c]: %m%n")))
            LogManager.getRootLogger().setLevel(Level.INFO)
            LogManager.getLogger("org.springframework.context").setLevel(Level.WARN)
        }
    }
}