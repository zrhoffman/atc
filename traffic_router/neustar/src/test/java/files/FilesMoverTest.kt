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
package files

import com.comcast.cdn.traffic_control.traffic_router.neustar.files.FilesMover

class FilesMoverTest {
    @Rule
    var parentFolder: TemporaryFolder? = TemporaryFolder()
    var currentFile1: File? = null
    var currentFile2: File? = null
    var tmpFolder: File? = null
    var newFile1: File? = null
    var newFile2: File? = null
    var oldFolder: File? = null
    var filesMover: FilesMover? = FilesMover()
    @Before
    @Throws(Exception::class)
    fun before() {
        tmpFolder = parentFolder.newFolder("tmp")
        oldFolder = parentFolder.newFolder("old")
        currentFile1 = parentFolder.newFile("data1.txt")
        var fileOutputStream: FileOutputStream? = FileOutputStream(currentFile1)
        fileOutputStream.write("currentFile1".getBytes())
        fileOutputStream.close()
        currentFile2 = parentFolder.newFile("current2.txt")
        fileOutputStream = FileOutputStream(currentFile2)
        fileOutputStream.write("currentFile2".getBytes())
        fileOutputStream.close()
        newFile1 = File(tmpFolder, "data1.txt")
        fileOutputStream = FileOutputStream(newFile1)
        fileOutputStream.write("new file 1".getBytes())
        fileOutputStream.close()
        newFile2 = File(tmpFolder, "new2.txt")
        fileOutputStream = FileOutputStream(newFile2)
        fileOutputStream.write("new file 2".getBytes())
        fileOutputStream.close()
    }

    @Test
    fun itPurgesDirectory() {
        assertThat(filesMover.purgeDirectory(tmpFolder), equalTo(true))
        assertThat(tmpFolder.list().length, equalTo(0))
    }

    @Test
    fun itMovesContents() {
        assertThat(filesMover.moveFiles(parentFolder.getRoot(), oldFolder), equalTo(true))
        assertThat(Arrays.asList(oldFolder.list()), containsInAnyOrder("data1.txt", "current2.txt"))
    }

    @Test
    @Throws(Exception::class)
    fun itUpdatesCurrent() {
        val updated: Boolean = filesMover.updateCurrent(parentFolder.getRoot(), tmpFolder, oldFolder)
        assertThat(updated, equalTo(true))
        assertThat(
            Arrays.asList(parentFolder.getRoot().list()),
            containsInAnyOrder("data1.txt", "new2.txt", "tmp", "old")
        )
        val file = File(parentFolder.getRoot(), "data1.txt")
        val fileInputStream = FileInputStream(file)
        val buffer = ByteArray(64)
        val numBytes: Int = fileInputStream.read(buffer)
        assertThat(String(buffer, 0, numBytes), equalTo("new file 1"))
        assertThat(oldFolder.list().length, equalTo(0))
    }
}