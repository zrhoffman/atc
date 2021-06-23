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

import com.comcast.cdn.traffic_control.traffic_router.neustar.files.FilesMover

class NeustarDatabaseUpdater {
    private val LOGGER: Logger? = Logger.getLogger(NeustarDatabaseUpdater::class.java)

    @Autowired
    private var neustarPollingTimeout: Integer? = null

    @Autowired
    private var neustarDataUrl: String? = null

    @Autowired
    private val neustarDatabaseDirectory: File? = null

    @Autowired
    private val neustarOldDatabaseDirectory: File? = null

    @Autowired
    private val filesMover: FilesMover? = null
    private var httpClient: HttpClient? = HttpClient()

    @Autowired
    private val tarExtractor: TarExtractor? = null
    fun setHttpClient(httpClient: HttpClient?) {
        this.httpClient = httpClient
    }

    private fun createTmpDir(directory: File?): File? {
        try {
            return Files.createTempDirectory(directory.toPath(), "neustar-").toFile()
        } catch (e: IOException) {
            System.out.println(
                "Failed to create temporary directory in " + directory.getAbsolutePath()
                    .toString() + ": " + e.getMessage()
            )
        }
        return null
    }

    fun verifyNewDatabase(directory: File?): Boolean {
        return try {
            Builder(directory).build()
            true
        } catch (e: Exception) {
            LOGGER.error("Database Directory " + directory + " is not a valid Neustar database. " + e.getMessage())
            false
        }
    }

    fun update(): Boolean {
        if (neustarDataUrl == null || neustarDataUrl.isEmpty()) {
            LOGGER.error("Cannot get latest neustar data 'neustar.polling.url' needs to be set in environment or properties file")
            return false
        }
        val tmpDir: File = createTmpDir(neustarDatabaseDirectory) ?: return false
        try {
            getRemoteDataResponse(URI.create(neustarDataUrl)).use { response ->
                if (response.getStatusLine().getStatusCode() === 304) {
                    LOGGER.info("Neustar database unchanged at $neustarDataUrl")
                    return false
                }
                if (response.getStatusLine().getStatusCode() !== 200) {
                    LOGGER.error(
                        "Failed downloading remote neustar database from " + neustarDataUrl + " " + response.getStatusLine()
                            .getReasonPhrase()
                    )
                }
                if (!enoughFreeSpace(tmpDir, response, neustarDataUrl)) {
                    return false
                }
                GZIPInputStream(response.getEntity().getContent()).use { gzipStream ->
                    if (!tarExtractor.extractTo(tmpDir, gzipStream)) {
                        LOGGER.error("Failed to decompress remote content from $neustarDataUrl")
                        return false
                    }
                }
                LOGGER.info(
                    "Replacing neustar files in " + neustarDatabaseDirectory.getAbsolutePath()
                        .toString() + " with those in " + tmpDir.getAbsolutePath()
                )
                if (!filesMover.updateCurrent(neustarDatabaseDirectory, tmpDir, neustarOldDatabaseDirectory)) {
                    LOGGER.error("Failed updating neustar files")
                    return false
                }
                if (!verifyNewDatabase(tmpDir)) {
                    return false
                }
            }
        } catch (e: Exception) {
            LOGGER.error("Failed getting remote neustar data: " + e.getMessage())
        } finally {
            httpClient.close()
            if (!filesMover.purgeDirectory(tmpDir) || !tmpDir.delete()) {
                LOGGER.error("Failed purging temporary directory " + tmpDir.getAbsolutePath())
            }
        }
        return true
    }

    fun getRemoteDataResponse(uri: URI?): CloseableHttpResponse? {
        val httpGet = HttpGet(uri)
        httpGet.setConfig(RequestConfig.custom().setSocketTimeout(neustarPollingTimeout).build())
        val buildDate: Date? = getDatabaseBuildDate()
        if (buildDate != null) {
            httpGet.setHeader("If-Modified-Since", SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z").format(buildDate))
        }
        return httpClient.execute(httpGet)
    }

    fun enoughFreeSpace(destination: File?, response: HttpResponse?, request: String?): Boolean {
        val contentLengthHeader: Header = response.getFirstHeader("Content-Length")
        if (contentLengthHeader == null) {
            LOGGER.warn("Unable to determine size of data from $request")
            return true
        }
        val contentLength: Long = parseLong(contentLengthHeader.getValue())
        val freespace: Long = destination.getFreeSpace()
        if (freespace < contentLength) {
            LOGGER.error("Not enough space in $destination to save $request(Free: $freespace, Need: $contentLength")
            return false
        }
        return true
    }

    fun getDatabaseBuildDate(): Date? {
        val neustarDatabaseFiles: Array<File?> = neustarDatabaseDirectory.listFiles()
        if (neustarDatabaseFiles == null || neustarDatabaseFiles.size == 0) {
            return null
        }
        var modifiedTimestamp: Long = 0
        for (file in neustarDatabaseFiles) {
            if (file.isDirectory()) {
                continue
            }
            if (modifiedTimestamp == 0L || file.lastModified() < modifiedTimestamp) {
                modifiedTimestamp = file.lastModified()
            }
        }
        return if (modifiedTimestamp > 0) Date(modifiedTimestamp) else null
    }

    fun setNeustarDataUrl(neustarDataUrl: String?) {
        this.neustarDataUrl = neustarDataUrl
    }

    fun setNeustarPollingTimeout(neustarPollingTimeout: Int) {
        this.neustarPollingTimeout = neustarPollingTimeout
    }
}