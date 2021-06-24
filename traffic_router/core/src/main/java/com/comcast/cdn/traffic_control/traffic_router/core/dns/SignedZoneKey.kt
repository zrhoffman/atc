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
package com.comcast.cdn.traffic_control.traffic_router.core.dns

import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignedZoneKey
import org.apache.log4j.Logger
import org.xbill.DNS.Name
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.Record
import java.util.Calendar

class SignedZoneKey(name: Name?, records: MutableList<Record?>?) : ZoneKey(name, records) {
    private var minimumSignatureExpiration: Calendar? = null
    private var kskExpiration: Calendar? = null
    private var zskExpiration: Calendar? = null
    fun getMinimumSignatureExpiration(): Calendar? {
        return minimumSignatureExpiration
    }

    fun setMinimumSignatureExpiration(signedRecords: MutableList<Record?>?, defaultExpiration: Calendar?) {
        val minSignatureExpiration = signedRecords.stream()
            .filter { r: Record? -> r is RRSIGRecord }
            .mapToLong { r: Record? -> (r as RRSIGRecord?).getExpire().time }
            .min()
        if (!minSignatureExpiration.isPresent) {
            SignedZoneKey.Companion.LOGGER.error("unable to calculate minimum signature expiration: no RRSIG records given")
            minimumSignatureExpiration = defaultExpiration
            return
        }
        val tmp = Calendar.getInstance()
        tmp.timeInMillis = minSignatureExpiration.asLong
        minimumSignatureExpiration = tmp
    }

    fun getSignatureDuration(): Long {
        return minimumSignatureExpiration.getTimeInMillis() - timestamp
    }

    fun getRefreshHorizon(): Long {
        return timestamp + Math.round(getSignatureDuration() as Double / 2.0) // force a refresh when we're halfway through our validity period
    }

    fun getEarliestSigningKeyExpiration(): Long {
        return if (getKSKExpiration().before(getZSKExpiration())) {
            getKSKExpiration().getTimeInMillis()
        } else {
            getZSKExpiration().getTimeInMillis()
        }
    }

    fun getKSKExpiration(): Calendar? {
        return kskExpiration
    }

    fun setKSKExpiration(kskExpiration: Calendar?) {
        this.kskExpiration = kskExpiration
    }

    fun getZSKExpiration(): Calendar? {
        return zskExpiration
    }

    fun setZSKExpiration(zskExpiration: Calendar?) {
        this.zskExpiration = zskExpiration
    }

    companion object {
        private val LOGGER = Logger.getLogger(SignedZoneKey::class.java)
    }
}