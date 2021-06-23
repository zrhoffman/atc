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
package com.comcast.cdn.traffic_control.traffic_router.neustar.data

import org.apache.commons.compress.archivers.tar.TarArchiveEntry

class TarExtractor {
    private val LOGGER: Logger? = Logger.getLogger(TarExtractor::class.java)
    fun extractTo(directory: File?, inputStream: InputStream?): Boolean {
        try {
            TarArchiveInputStream(inputStream).use { tarArchiveInputStream ->
                var tarArchiveEntry: TarArchiveEntry?
                while (tarArchiveInputStream.getNextTarEntry().also { tarArchiveEntry = it } != null) {
                    if (tarArchiveEntry.isDirectory()) {
                        continue
                    }
                    val file = File(directory, tarArchiveEntry.getName())
                    LOGGER.info(
                        "Extracting Tarfile entry " + tarArchiveEntry.getName()
                            .toString() + " to temporary location " + file.getAbsolutePath()
                    )
                    if (!file.exists() && !file.createNewFile()) {
                        LOGGER.warn(
                            "Failed to extract file to " + file.getAbsolutePath()
                                .toString() + ", cannot create file, check permissions of " + directory.getAbsolutePath()
                        )
                        return false
                    }
                    copyInputStreamToFile(tarArchiveInputStream, file)
                }
            }
        } catch (e: IOException) {
            LOGGER.error(
                "Failed extracting tar archive to directory " + directory.getAbsolutePath()
                    .toString() + " : " + e.getMessage()
            )
            return false
        }
        return true
    }

    @Throws(IOException::class)
    protected fun copyInputStreamToFile(inputStream: InputStream?, file: File?) {
        val buffer = ByteArray(50 * 1024 * 1024)
        var bytesRead: Int
        FileOutputStream(file).use { outputStream ->
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                outputStream.write(buffer, 0, bytesRead)
            }
        }
    }
}