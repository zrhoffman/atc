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
package shared

import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificates
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.Mockito
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import javax.management.AttributeChangeNotification

@RunWith(PowerMockRunner::class)
@PrepareForTest(DeliveryServiceCertificates::class, System::class)
class DeliveryServiceCertificatesTest {
    @Before
    @Throws(Exception::class)
    fun before() {
        PowerMockito.mockStatic(System::class.java)
        Mockito.`when`(System.currentTimeMillis()).thenReturn(1234L)
    }

    @Test
    fun itSendsNotificationWhenNewCertData() {
        val deliveryServiceCertificates = Mockito.spy(DeliveryServiceCertificates())
        val captor = ArgumentCaptor.forClass(
            AttributeChangeNotification::class.java
        )
        val certificateDataList: MutableList<CertificateData?> = ArrayList()
        deliveryServiceCertificates.certificateDataList = certificateDataList
        Mockito.verify(deliveryServiceCertificates, Mockito.times(1)).sendNotification(captor.capture())
        val notification = captor.value
        MatcherAssert.assertThat(notification.newValue, CoreMatchers.equalTo(certificateDataList))
        MatcherAssert.assertThat(notification.attributeName, CoreMatchers.equalTo("CertificateDataList"))
        MatcherAssert.assertThat(notification.attributeType, CoreMatchers.equalTo("List<CertificateData>"))
        MatcherAssert.assertThat(notification.message, CoreMatchers.equalTo("CertificateDataList Changed"))
        MatcherAssert.assertThat(notification.timeStamp, CoreMatchers.equalTo(1234L))
        MatcherAssert.assertThat(notification.sequenceNumber, CoreMatchers.equalTo(1L))
        MatcherAssert.assertThat(notification.source, CoreMatchers.equalTo(deliveryServiceCertificates))
    }
}