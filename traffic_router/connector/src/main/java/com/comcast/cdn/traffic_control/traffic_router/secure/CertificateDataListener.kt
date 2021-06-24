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
package com.comcast.cdn.traffic_control.traffic_router.secure

import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDataListener
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import org.apache.log4j.Logger
import javax.management.AttributeChangeNotification
import javax.management.Notification
import javax.management.NotificationListener

class CertificateDataListener : NotificationListener {
    override fun handleNotification(notification: Notification?, handback: Any?) {
        if (notification !is AttributeChangeNotification) {
            return
        }
        var certificateDataList: MutableList<CertificateData?> = ArrayList()
        val newValue = (notification as AttributeChangeNotification?).getNewValue()
        if (certificateDataList.javaClass.isInstance(newValue)) {
            certificateDataList = newValue as MutableList<CertificateData?>
            try {
                CertificateRegistry.Companion.getInstance().importCertificateDataList(certificateDataList)
            } catch (t: Throwable) {
                CertificateDataListener.Companion.log.warn(
                    "Failed importing certificate data list into registry " + t.javaClass.simpleName,
                    t
                )
            }
        }
    }

    companion object {
        private val log = Logger.getLogger(CertificateDataListener::class.java)
    }
}