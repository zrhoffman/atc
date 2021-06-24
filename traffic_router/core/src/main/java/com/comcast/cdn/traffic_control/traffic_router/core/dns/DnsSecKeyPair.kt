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
import java.util.Date

interface DnsSecKeyPair {
    open fun getTTL(): Long
    open fun setTTL(ttl: Long)
    open fun getName(): String?
    open fun setName(name: String?)
    open fun getInception(): Date?
    open fun setInception(inception: Date?)
    open fun getEffective(): Date?
    open fun setEffective(effective: Date?)
    open fun getExpiration(): Date?
    open fun setExpiration(expiration: Date?)
    open fun isKeySigningKey(): Boolean
    open fun isExpired(): Boolean
    open fun isUsable(): Boolean
    open fun isKeyCached(maxTTL: Long): Boolean
    open fun isOlder(other: DnsSecKeyPair?): Boolean
    open fun isNewer(other: DnsSecKeyPair?): Boolean
    open fun getPrivate(): PrivateKey?
    open fun getPublic(): PublicKey?
    open fun getDNSKEYRecord(): DNSKEYRecord?
    override fun equals(obj: Any?): Boolean
    override fun toString(): String
}