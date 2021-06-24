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
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificates
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import com.comcast.cdn.traffic_control.traffic_router.tomcat.TomcatLifecycleListener
import org.apache.catalina.Lifecycle
import org.apache.catalina.LifecycleEvent
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito
import org.mockito.invocation.InvocationOnMock
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import java.lang.management.ManagementFactory
import java.util.Arrays
import java.util.function.Consumer
import javax.management.MBeanServer
import javax.management.ObjectName

@RunWith(PowerMockRunner::class)
@PrepareForTest(TomcatLifecycleListener::class, ManagementFactory::class, LifecycleEvent::class)
class TomcatLifecycleListenerTest {
    @Before
    fun before() {
        PowerMockito.mockStatic(ManagementFactory::class.java)
    }

    @Test
    fun itIgnoresNonInitEvents() {
        Mockito.`when`(ManagementFactory.getPlatformMBeanServer())
            .thenThrow(RuntimeException("invoked getPlatformMBeanServer"))
        val lifecycle = Mockito.mock(Lifecycle::class.java)
        val tomcatLifecycleListener = TomcatLifecycleListener()
        Arrays.asList(
            Lifecycle.AFTER_START_EVENT,
            Lifecycle.AFTER_STOP_EVENT,
            Lifecycle.BEFORE_START_EVENT,
            Lifecycle.BEFORE_STOP_EVENT,
            Lifecycle.PERIODIC_EVENT,
            Lifecycle.START_EVENT,
            Lifecycle.STOP_EVENT
        ).forEach(Consumer { s: String? ->
            tomcatLifecycleListener.lifecycleEvent(
                LifecycleEvent(
                    lifecycle,
                    s,
                    Any()
                )
            )
        })
    }

    @Test
    @Throws(Exception::class)
    fun itRegistersBeanAndAddsListenerOnInit() {
        val mBeanServer = Mockito.mock(MBeanServer::class.java)
        Mockito.`when`(ManagementFactory.getPlatformMBeanServer())
            .thenAnswer { invocationOnMock: InvocationOnMock? -> mBeanServer }
        val certificateDataListener = Mockito.mock(
            CertificateDataListener::class.java
        )
        val tomcatLifecycleListener = TomcatLifecycleListener()
        tomcatLifecycleListener.certificateDataListener = certificateDataListener
        val lifecycleEvent = PowerMockito.mock(LifecycleEvent::class.java)
        PowerMockito.`when`(lifecycleEvent.type).thenReturn(Lifecycle.AFTER_INIT_EVENT)
        tomcatLifecycleListener.lifecycleEvent(lifecycleEvent)
        val name = ObjectName(DeliveryServiceCertificatesMBean.Companion.OBJECT_NAME)
        Mockito.verify(mBeanServer).registerMBean(DeliveryServiceCertificates(), name)
        Mockito.verify(mBeanServer).addNotificationListener(name, certificateDataListener, null, null)
    }
}