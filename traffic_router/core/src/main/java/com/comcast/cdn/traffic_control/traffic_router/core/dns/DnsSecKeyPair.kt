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
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*

open interface DnsSecKeyPair {
    var ttl: Long
    var name: String
    var inception: Date
    var effective: Date
    var expiration: Date
    val isKeySigningKey: Boolean
    val isExpired: Boolean
    val isUsable: Boolean
    fun isKeyCached(maxTTL: Long): Boolean
    fun isOlder(other: DnsSecKeyPair): Boolean
    fun isNewer(other: DnsSecKeyPair): Boolean
    val private: PrivateKey?
    val public: PublicKey?
    val dNSKEYRecord: DNSKEYRecord?
    public override fun equals(obj: Any?): Boolean
    public override fun toString(): String
}