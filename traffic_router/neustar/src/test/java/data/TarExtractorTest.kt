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

import com.comcast.cdn.traffic_control.traffic_router.neustar.data.TarExtractor

@RunWith(PowerMockRunner::class)
@PrepareForTest([TarExtractor::class, File::class, TarArchiveInputStream::class])
class TarExtractorTest {
    @Before
    fun before() {
        LogManager.getRootLogger().addAppender(ConsoleAppender(PatternLayout("%d %-5p [%c]: %m%n")))
    }

    @Test
    @Throws(Exception::class)
    fun itExtractsTarFile() {
        val tarArchiveInputStream: TarArchiveInputStream = mock(TarArchiveInputStream::class.java)
        whenNew(TarArchiveInputStream::class.java).withArguments(any(InputStream::class.java))
            .thenReturn(tarArchiveInputStream)
        `when`(tarArchiveInputStream.getNextTarEntry()).thenAnswer(object : Answer() {
            private var count = 0
            fun answer(invocationOnMock: InvocationOnMock?): Object? {
                count++
                if (count == 1) {
                    val tarArchiveEntry: TarArchiveEntry = mock(TarArchiveEntry::class.java)
                    `when`(tarArchiveEntry.getName()).thenReturn("data.gpdb")
                    `when`(tarArchiveEntry.isFile()).thenReturn(true)
                    return tarArchiveEntry
                }
                if (count == 2) {
                    val tarArchiveEntry: TarArchiveEntry = mock(TarArchiveEntry::class.java)
                    `when`(tarArchiveEntry.getName()).thenReturn("IpV6Data")
                    `when`(tarArchiveEntry.isDirectory()).thenReturn(true)
                    return tarArchiveEntry
                }
                return null
            }
        })
        val directory: File = mock(File::class.java)
        val fileInTar: File = spy(mock(File::class.java))
        `when`(fileInTar.createNewFile()).thenReturn(true)
        whenNew(File::class.java).withArguments(directory, "data.gpdb").thenReturn(fileInTar)
        val directoryInTar: File = spy(mock(File::class.java))
        `when`(directoryInTar.createNewFile()).thenReturn(true)
        whenNew(File::class.java).withArguments(directory, "IpV6Data").thenReturn(directoryInTar)
        val fileOutputStream: FileOutputStream = mock(FileOutputStream::class.java)
        whenNew(FileOutputStream::class.java).withArguments(fileInTar).thenReturn(fileOutputStream)
        `when`(tarArchiveInputStream.read(any(ByteArray::class.java))).thenAnswer(object : Answer() {
            private var count = 0
            fun answer(invocationOnMock: InvocationOnMock?): Object? {
                count++
                return if (count == 1) Integer(654321) else Integer(-1)
            }
        })
        val inputStream1: InputStream = mock(InputStream::class.java)
        val tarExtractor = TarExtractor()
        assertThat(tarExtractor.extractTo(directory, inputStream1), equalTo(true))
        verify(fileInTar).createNewFile()
        verify(fileOutputStream).write(any(ByteArray::class.java), eq(0), eq(654321))
        verify(fileOutputStream).close()
        verifyNoMoreInteractions(fileOutputStream)
        verifyZeroInteractions(directoryInTar)
    }

    internal inner class SimpleFilenameFilter : FileFilter {
        var name: String? = null

        @Override
        fun accept(pathname: File?): Boolean {
            return name.equals(pathname.getName())
        }
    }
}