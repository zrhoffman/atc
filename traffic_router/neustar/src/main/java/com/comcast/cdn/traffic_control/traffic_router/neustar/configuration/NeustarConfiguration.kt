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
package com.comcast.cdn.traffic_control.traffic_router.neustar.configuration

import com.comcast.cdn.traffic_control.traffic_router.neustar.NeustarGeolocationService

@Configuration
@PropertySource(value = "neustar.properties", ignoreResourceNotFound = true)
class NeustarConfiguration {
    private val LOGGER: Logger? = Logger.getLogger(NeustarConfiguration::class.java)

    @Autowired
    private val environment: Environment? = null

    @Autowired
    private val databasesDir: Path? = null
    var neustarDatabaseUpdater: NeustarDatabaseUpdater? = null
    var neustarGeolocationService: NeustarGeolocationService? = null
    private var neustarDatabaseDirectory: File? = null
    private var neustarOldDatabaseDirectory: File? = null
    private fun checkDirectory(directory: File?): File? {
        if (!directory.exists() && !directory.mkdirs()) {
            LOGGER.error(directory.getAbsolutePath().toString() + " does not exist and cannot be created")
        }
        return directory
    }

    @Bean
    fun neustarDatabaseDirectory(): File? {
        if (neustarDatabaseDirectory == null) {
            neustarDatabaseDirectory = checkDirectory(
                databasesDir.resolve(environment.getProperty("neustar.subdirectory", "neustar")).toFile()
            )
        }
        return neustarDatabaseDirectory
    }

    @Bean
    fun neustarOldDatabaseDirectory(): File? {
        if (neustarOldDatabaseDirectory == null) {
            neustarOldDatabaseDirectory = checkDirectory(File(neustarDatabaseDirectory(), "/old"))
        }
        return neustarOldDatabaseDirectory
    }

    @Bean
    fun filesMover(): FilesMover? {
        return FilesMover()
    }

    @Bean
    fun tarExtractor(): TarExtractor? {
        return TarExtractor()
    }

    @Bean
    fun neustarRemoteSource(): String? {
        val pollingUri: String = environment.getProperty("neustar.polling.url")
        if (pollingUri == null || pollingUri.isEmpty()) {
            LOGGER.error("'neustar.polling.url' must be set in the environment or file 'neustar.properties' on the classpath")
        }
        LOGGER.info("Using $pollingUri for 'neustar.polling.url'")
        return pollingUri
    }

    @Bean
    fun neustarPollingTimeout(): Integer? {
        return environment.getProperty("neustar.polling.timeout", Integer::class.java, 30000)
    }

    @Bean
    fun neustarDatabaseUpdater(): NeustarDatabaseUpdater? {
        if (neustarDatabaseUpdater == null) {
            neustarDatabaseUpdater = NeustarDatabaseUpdater()
        }
        return neustarDatabaseUpdater
    }

    @Bean
    fun neustarGeolocationService(): NeustarGeolocationService? {
        if (neustarGeolocationService == null) {
            neustarGeolocationService = NeustarGeolocationService()
        }
        return neustarGeolocationService
    }

    @Bean
    fun serviceRefresher(): ServiceRefresher? {
        return ServiceRefresher()
    }

    @Bean
    fun scheduledExecutorService(): ScheduledExecutorService? {
        return Executors.newSingleThreadScheduledExecutor()
    }

    @Bean
    fun trafficRouterConfigurationListener(): ConfigurationListener? {
        return TrafficRouterConfigurationListener()
    }
}