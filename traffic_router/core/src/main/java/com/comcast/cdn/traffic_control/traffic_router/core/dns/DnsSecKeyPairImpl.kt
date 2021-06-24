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

import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPairImpl
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.secure.BindPrivateKey
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger
import org.xbill.DNS.DNSKEYRecord
import org.xbill.DNS.DNSSEC.DNSSECException
import org.xbill.DNS.Master
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Type
import java.io.ByteArrayInputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64
import java.util.Calendar
import java.util.Date

class DnsSecKeyPairImpl(keyPair: JsonNode?, defaultTTL: Long) : DnsSecKeyPair {
    private var ttl: Long
    private var inception: Date?
    private var effective: Date?
    private var expiration: Date?
    private var name: String?
    private val dnskeyRecord: DNSKEYRecord? = null
    private val privateKey: PrivateKey? = null
    override fun getTTL(): Long {
        return ttl
    }

    override fun setTTL(ttl: Long) {
        this.ttl = ttl
    }

    override fun getName(): String? {
        return name
    }

    override fun setName(name: String?) {
        this.name = name
    }

    override fun getInception(): Date? {
        return inception
    }

    override fun setInception(inception: Date?) {
        this.inception = inception
    }

    override fun getEffective(): Date? {
        return effective
    }

    override fun setEffective(effective: Date?) {
        this.effective = effective
    }

    override fun getExpiration(): Date? {
        return expiration
    }

    override fun setExpiration(expiration: Date?) {
        this.expiration = expiration
    }

    override fun isKeySigningKey(): Boolean {
        return getDNSKEYRecord().getFlags() and DNSKEYRecord.Flags.SEP_KEY != 0
    }

    override fun isExpired(): Boolean {
        return getExpiration().before(Calendar.getInstance().time)
    }

    override fun isUsable(): Boolean {
        val now = Calendar.getInstance().time
        return getEffective().before(now)
    }

    override fun isKeyCached(maxTTL: Long): Boolean {
        return getExpiration().after(Date(System.currentTimeMillis() - maxTTL * 1000))
    }

    override fun isOlder(other: DnsSecKeyPair?): Boolean {
        return getEffective().before(other.getEffective())
    }

    override fun isNewer(other: DnsSecKeyPair?): Boolean {
        return getEffective().after(other.getEffective())
    }

    override fun getDNSKEYRecord(): DNSKEYRecord? {
        return dnskeyRecord
    }

    override fun getPrivate(): PrivateKey? {
        return privateKey
    }

    override fun getPublic(): PublicKey? {
        try {
            return dnskeyRecord.getPublicKey()
        } catch (e: DNSSECException) {
            DnsSecKeyPairImpl.Companion.LOGGER.error(
                "Failed to extract public key from DNSKEY record for " + name + " : " + e.message,
                e
            )
        }
        return null
    }

    override fun equals(obj: Any?): Boolean {
        val okp = obj as DnsSecKeyPairImpl?
        if (getDNSKEYRecord() != okp.getDNSKEYRecord()) {
            return false
        } else if (this.private != okp.getPrivate()) {
            return false
        } else if (this.public != okp.getPublic()) {
            return false
        } else if (getEffective() != okp.getEffective()) {
            return false
        } else if (getExpiration() != okp.getExpiration()) {
            return false
        } else if (getInception() != okp.getInception()) {
            return false
        } else if (getName() != okp.getName()) {
            return false
        } else if (getTTL() != okp.getTTL()) {
            return false
        }
        return true
    }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("name=").append(name)
            .append(" ttl=").append(getTTL())
            .append(" ksk=").append(isKeySigningKey)
            .append(" inception=\"")
        sb.append(getInception())
        sb.append("\" effective=\"")
        sb.append(getEffective())
        sb.append("\" expiration=\"")
        sb.append(getExpiration()).append('"')
        return sb.toString()
    }

    companion object {
        private val LOGGER = Logger.getLogger(DnsSecKeyPairImpl::class.java)
    }

    init {
        inception = Date(1000L * JsonUtils.getLong(keyPair, "inceptionDate"))
        effective = Date(1000L * JsonUtils.getLong(keyPair, "effectiveDate"))
        expiration = Date(1000L * JsonUtils.getLong(keyPair, "expirationDate"))
        ttl = JsonUtils.optLong(keyPair, "ttl", defaultTTL)
        name = JsonUtils.getString(keyPair, "name").toLowerCase()
        val mimeDecoder = Base64.getMimeDecoder()
        try {
            privateKey = BindPrivateKey().decode(String(mimeDecoder.decode(JsonUtils.getString(keyPair, "private"))))
        } catch (e: Exception) {
            DnsSecKeyPairImpl.Companion.LOGGER.error("Failed to decode PKCS1 key from json data!: " + e.message, e)
        }
        val publicKey = mimeDecoder.decode(JsonUtils.getString(keyPair, "public"))
        ByteArrayInputStream(publicKey).use { `in` ->
            val master = Master(`in`, Name(name), ttl)
            var record: Record?
            while (master.nextRecord().also { record = it } != null) {
                if (record.getType() == Type.DNSKEY) {
                    dnskeyRecord = record as DNSKEYRecord?
                    break
                }
            }
        }
    }
}