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
package secure

import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDataListener
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateRegistry
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Matchers
import org.mockito.Mockito
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import java.util.Arrays
import javax.management.AttributeChangeNotification
import javax.management.Notification

@RunWith(PowerMockRunner::class)
@PrepareForTest(CertificateRegistry::class)
class CertificateDataListenerTest {
    private var certificateRegistry: CertificateRegistry? = null

    @Before
    @Throws(Exception::class)
    fun before() {
        certificateRegistry = Mockito.mock(CertificateRegistry::class.java)
        PowerMockito.mockStatic(CertificateRegistry::class.java)
        Mockito.`when`<CertificateRegistry?>(CertificateRegistry.Companion.getInstance())
            .thenReturn(certificateRegistry)
    }

    @Test
    @Throws(Exception::class)
    fun itImportsCertificateDataToRegistry() {
        val oldList: MutableList<CertificateData?> = ArrayList()
        val newList: MutableList<CertificateData?> = ArrayList()
        val notifier: Any = "notifier"
        val notification: Notification = AttributeChangeNotification(
            notifier, 1L, System.currentTimeMillis(),
            "CertificateDataList Changed", "CertificateDataList", "List<CertificateDataList>", oldList, newList
        )
        val certificateDataListener = CertificateDataListener()
        certificateDataListener.handleNotification(notification, null)
        Mockito.verify(certificateRegistry).importCertificateDataList(newList)
    }

    @Test
    @Throws(Exception::class)
    fun itIgnoresBadInput() {
        var notification = Notification("notifier", "source", 1L, "hello world")
        val certificateDataListener = CertificateDataListener()
        certificateDataListener.handleNotification(notification, null)
        Mockito.verify(certificateRegistry, Mockito.times(0)).importCertificateDataList(Matchers.any())
        val badData = Arrays.asList("foo", "bar", "baz")
        notification = AttributeChangeNotification(
            "notifier", 1L, System.currentTimeMillis(),
            "CertificateDataList Changed", "CertificateDataList", "List<CertificateDataList>", null, badData
        )
        certificateDataListener.handleNotification(notification, null)
        Mockito.verify(certificateRegistry, Mockito.times(0)).importCertificateDataList(Matchers.any())
    }
}