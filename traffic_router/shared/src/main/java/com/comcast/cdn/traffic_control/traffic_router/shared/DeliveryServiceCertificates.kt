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
package com.comcast.cdn.traffic_control.traffic_router.shared

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import javax.management.AttributeChangeNotification
import javax.management.NotificationBroadcasterSupport

class DeliveryServiceCertificates : NotificationBroadcasterSupport(), DeliveryServiceCertificatesMBean {
    private var certificateDataList: MutableList<CertificateData?>? = null
    private var sequenceNumber = 1L
    override fun getCertificateDataList(): MutableList<CertificateData?>? {
        return certificateDataList
    }

    override fun setCertificateDataList(certificateDataList: MutableList<CertificateData?>?) {
        val oldCertificateDataList = this.certificateDataList
        this.certificateDataList = certificateDataList
        sendNotification(
            AttributeChangeNotification(
                this, sequenceNumber, System.currentTimeMillis(), "CertificateDataList Changed",
                "CertificateDataList", "List<CertificateData>", oldCertificateDataList, this.certificateDataList
            )
        )
        sequenceNumber++
    }

    override fun setCertificateDataListString(certificateDataListString: String?) {
        try {
            val certificateDataList = ObjectMapper().readValue<MutableList<CertificateData?>?>(
                certificateDataListString,
                object : TypeReference<MutableList<CertificateData?>?>() {})
            setCertificateDataList(certificateDataList)
        } catch (e: Exception) {
            throw RuntimeException("Failed to convert json certificate data list to list of CertificateData objects", e)
        }
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as DeliveryServiceCertificates?
        if (sequenceNumber != that.sequenceNumber) {
            return false
        }
        return if (certificateDataList != null) certificateDataList == that.certificateDataList else that.certificateDataList == null
    }

    override fun hashCode(): Int {
        var result = if (certificateDataList != null) certificateDataList.hashCode() else 0
        result = 31 * result + (sequenceNumber xor (sequenceNumber ushr 32)) as Int
        return result
    }
}