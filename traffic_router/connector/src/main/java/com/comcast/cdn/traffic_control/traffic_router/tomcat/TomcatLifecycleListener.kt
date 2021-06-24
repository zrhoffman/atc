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
package com.comcast.cdn.traffic_control.traffic_router.tomcat

import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDataListener
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificates
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import org.apache.catalina.Lifecycle
import org.apache.catalina.LifecycleEvent
import org.apache.catalina.LifecycleListener
import org.apache.log4j.Logger
import java.lang.management.ManagementFactory
import javax.management.ObjectName

class TomcatLifecycleListener : LifecycleListener {
    private var certificateDataListener: CertificateDataListener? = CertificateDataListener()
    override fun lifecycleEvent(event: LifecycleEvent?) {
        if (Lifecycle.AFTER_INIT_EVENT != event.getType()) {
            return
        }
        try {
            TomcatLifecycleListener.Companion.log.info("Registering delivery service certificates mbean")
            val objectName = ObjectName(DeliveryServiceCertificatesMBean.Companion.OBJECT_NAME)
            val platformMBeanServer = ManagementFactory.getPlatformMBeanServer()
            platformMBeanServer.registerMBean(DeliveryServiceCertificates(), objectName)
            platformMBeanServer.addNotificationListener(objectName, certificateDataListener, null, null)
        } catch (e: Exception) {
            throw RuntimeException(
                "Failed to register MBean " + DeliveryServiceCertificatesMBean.Companion.OBJECT_NAME + " " + e.javaClass.simpleName + ": " + e.message,
                e
            )
        }
    }

    fun getCertificateDataListener(): CertificateDataListener? {
        return certificateDataListener
    }

    fun setCertificateDataListener(certificateDataListener: CertificateDataListener?) {
        this.certificateDataListener = certificateDataListener
    }

    companion object {
        private val log = Logger.getLogger(LifecycleListener::class.java)
    }
}