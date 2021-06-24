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

import org.xbill.DNS.DNSKEYRecord
import org.xbill.DNS.DSRecord
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.Record
import java.io.IOException
import java.security.GeneralSecurityException
import java.util.Date
import java.util.concurrent.ConcurrentMap

interface ZoneSigner {
    @Throws(IOException::class, GeneralSecurityException::class)
    open fun signZone(
        records: MutableList<Record?>?, kskPairs: MutableList<DnsSecKeyPair?>?,
        zskPairs: MutableList<DnsSecKeyPair?>?, inception: Date?, expiration: Date?,
        RRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>?
    ): MutableList<Record?>?

    open fun calculateDSRecord(dnskeyRecord: DNSKEYRecord?, digestId: Int, ttl: Long): DSRecord?
}