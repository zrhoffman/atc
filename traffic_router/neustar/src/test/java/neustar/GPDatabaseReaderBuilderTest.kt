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
package neustar

import com.maxmind.db.Reader

@RunWith(PowerMockRunner::class)
class GPDatabaseReaderBuilderTest constructor() {
    @Test
    @Throws(Exception::class)
    fun buildThrowsExceptionForNullFile() {
        try {
            Builder(null).build()
            fail("Should have thrown exception!")
        } catch (e: IllegalArgumentException) {
            assertThat(e.getMessage(), equalTo("The directory is null."))
        }
    }

    @Test
    @Throws(Exception::class)
    fun buildThrowsExceptionForNondirectory() {
        try {
            val file: File? = mock(File::class.java)
            Builder(file).build()
            fail("Should have thrown exception!")
        } catch (e: IllegalArgumentException) {
            assertThat(e.getMessage(), containsString("is not a directory."))
        }
    }

    @Test
    @Throws(Exception::class)
    fun buildThrowsExceptionForEmptyDirectory() {
        try {
            val file: File? = mock(File::class.java)
            `when`(file.isDirectory()).thenReturn(true)
            Builder(file).build()
            fail("Should have thrown exception!")
        } catch (e: IOException) {
            assertThat(e.getMessage(), equalTo("Error to load the gpdb files."))
        }
    }

    @Test
    @PrepareForTest([GPDatabaseReader::class, Reader::class])
    @Throws(Exception::class)
    fun buildReturnsReaderForDirectoryWithGpdbFiles() {
        val gpdbFile: File? = mock(File::class.java)
        `when`(gpdbFile.getName()).thenReturn("dataV4.gpdb")
        `when`(gpdbFile.getPath()).thenReturn("/tmp/dataV4.gpdb")
        val file: File? = mock(File::class.java)
        whenNew(File::class.java).withArguments("/tmp/dataV4.gpdb").thenReturn(file)
        val reader: Reader? = mock(Reader::class.java)
        whenNew(Reader::class.java).withArguments(gpdbFile).thenReturn(reader)
        val directory: File? = mock(File::class.java)
        `when`(directory.isDirectory()).thenReturn(true)
        `when`(directory.listFiles()).thenReturn(arrayOf<File?>(gpdbFile))
        assertThat(Builder(directory).build(), notNullValue())
    }
}