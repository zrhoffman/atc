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
package org.apache.traffic_control.traffic_router.core.loc

import org.apache.traffic_control.traffic_router.core.router.TrafficRouterManager
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers
import org.mockito.Mockito
import org.powermock.api.mockito.PowerMockito
import org.powermock.api.support.membermodification.MemberMatcher
import org.powermock.api.support.membermodification.MemberModifier
import org.powermock.core.classloader.annotations.PowerMockIgnore
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import java.io.*
import java.nio.file.*

org.junit.*import java.io.*
import java.lang.Exceptionimport

java.net.*import java.nio.file.*

@RunWith(PowerMockRunner::class)
@PrepareForTest(AbstractServiceUpdater::class, HttpURLConnection::class, URL::class, Files::class)
@PowerMockIgnore("javax.management.*")
class AbstractServiceUpdaterTest {
    private var trafficRouterManager: TrafficRouterManager? = null
    private var connection: HttpURLConnection? = null
    private var databasesDirectory: Path? = null
    private var databasePath: Path? = null
    private var databaseFile: File? = null
    @Before
    @Throws(Exception::class)
    fun before() {
        databaseFile = Mockito.mock(File::class.java)
        Mockito.`when`(databaseFile.exists()).thenReturn(true)
        Mockito.`when`(databaseFile.lastModified()).thenReturn(1L)
        databasePath = Mockito.mock(Path::class.java)
        Mockito.`when`(databasePath.toFile()).thenReturn(databaseFile)
        databasesDirectory = Mockito.mock(Path::class.java)
        Mockito.`when`(databasesDirectory.resolve(ArgumentMatchers.isNull<Any?>() as String)).thenReturn(databasePath)
        trafficRouterManager = Mockito.mock(TrafficRouterManager::class.java)
        Mockito.doNothing().`when`(trafficRouterManager).trackEvent(ArgumentMatchers.any())
        PowerMockito.mockStatic(Files::class.java)
        MemberModifier.stub<Any?>(MemberMatcher.method(Files::class.java, "exists")).toReturn(true)
        connection = PowerMockito.mock(HttpURLConnection::class.java)
        Mockito.`when`(connection.getHeaderField("ETag")).thenReturn("version-1")
        Mockito.`when`(connection.getResponseCode()).thenReturn(304)
        val url = PowerMockito.mock(URL::class.java)
        MemberModifier.stub<Any?>(MemberMatcher.method(URL::class.java, "openConnection")).toReturn(connection)
        PowerMockito.whenNew(URL::class.java).withAnyArguments().thenReturn(url)
    }

    @Test
    @Throws(Exception::class)
    fun itUsesETag() {
        val updater = Updater()
        updater.setTrafficRouterManager(trafficRouterManager)
        updater.setDatabasesDirectory(databasesDirectory)
        updater.dataBaseURL = "http://www.example.com"
        updater.updateDatabase()
        Mockito.verify(connection, Mockito.times(0)).setRequestProperty(ArgumentMatchers.eq("If-None-Match"), ArgumentMatchers.anyString())
        Mockito.verify(connection).getHeaderField("ETag")
        updater.updateDatabase()
        Mockito.verify(connection).setRequestProperty(ArgumentMatchers.eq("If-None-Match"), ArgumentMatchers.anyString())
        Mockito.verify(connection, Mockito.times(2)).getHeaderField("ETag")
    }

    internal inner class Updater : AbstractServiceUpdater() {
        @Throws(IOException::class)
        override fun verifyDatabase(dbFile: File?): Boolean {
            return false
        }

        @Throws(IOException::class)
        override fun loadDatabase(): Boolean {
            return false
        }

        override fun isLoaded(): Boolean {
            return true
        }
    }
}