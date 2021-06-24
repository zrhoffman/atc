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

import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImpl
import org.apache.log4j.Logger
import org.xbill.DNS.DClass
import org.xbill.DNS.DNSKEYRecord
import org.xbill.DNS.DNSSEC
import org.xbill.DNS.DNSSEC.DNSSECException
import org.xbill.DNS.DSRecord
import org.xbill.DNS.NSECRecord
import org.xbill.DNS.Name
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.RRset
import org.xbill.DNS.Record
import org.xbill.DNS.SOARecord
import org.xbill.DNS.Type
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.util.Collections
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap
import java.util.function.BiFunction
import java.util.function.Consumer
import java.util.function.Function
import java.util.stream.Collectors
import java.util.stream.Stream
import java.util.stream.StreamSupport

class ZoneSignerImpl : ZoneSigner {
    private fun toRRStream(rrSet: RRset?): Stream<Record?>? {
        val iterable = Iterable<Record?> { rrSet.rrs(false) }
        return StreamSupport.stream(iterable.spliterator(), false)
    }

    private fun toRRSigStream(rrSset: RRset?): Stream<Record?>? {
        val iterable = Iterable<Record?> { rrSset.sigs() }
        return StreamSupport.stream(iterable.spliterator(), false)
    }

    private fun sign(
        rrset: RRset?,
        dnskeyRecord: DNSKEYRecord?,
        privateKey: PrivateKey?,
        inception: Date?,
        expiration: Date?
    ): RRSIGRecord? {
        return try {
            DNSSEC.sign(rrset, dnskeyRecord, privateKey, inception, expiration)
        } catch (e: DNSSECException) {
            val message = String.format(
                "Failed to sign Resource Record Set for %s %d %d %d : %s",
                dnskeyRecord.getName(),
                dnskeyRecord.getDClass(),
                dnskeyRecord.getType(),
                dnskeyRecord.getTTL(),
                e.message
            )
            ZoneSignerImpl.Companion.LOGGER.error(message, e)
            null
        }
    }

    private fun isSignatureAlmostExpired(inception: Date?, expiration: Date?, now: Date?): Boolean {
        // now is over halfway through validity period
        return now.getTime() > inception.getTime() + (expiration.getTime() - inception.getTime()) / 2
    }

    private fun signRRset(
        rrSet: RRset?, kskPairs: MutableList<DnsSecKeyPair?>?, zskPairs: MutableList<DnsSecKeyPair?>?,
        inception: Date?, expiration: Date?,
        RRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>?
    ): RRset? {
        val signatures: MutableList<RRSIGRecord?> = ArrayList()
        val pairs = if (rrSet.getType() == Type.DNSKEY) kskPairs else zskPairs
        val now = Date()
        pairs.forEach(Consumer { pair: DnsSecKeyPair? ->
            val dnskeyRecord = pair.getDNSKEYRecord()
            val privateKey = pair.getPrivate()
            var signature: RRSIGRecord? = null
            try {
                if (RRSIGCache == null) {
                    signature = sign(rrSet, dnskeyRecord, privateKey, inception, expiration)
                } else {
                    val sigMap = RRSIGCache.computeIfAbsent(
                        RRSIGCacheKey(privateKey.encoded, dnskeyRecord.algorithm),
                        Function<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?> { rrsigCacheKey: RRSIGCacheKey? -> ConcurrentHashMap() })
                    signature = sigMap.computeIfAbsent(
                        RRsetKey(rrSet),
                        Function { k: RRsetKey? -> sign(rrSet, dnskeyRecord, privateKey, inception, expiration) })
                    if (signature != null && isSignatureAlmostExpired(signature.timeSigned, signature.expire, now)) {
                        signature = sigMap.compute(
                            RRsetKey(rrSet),
                            BiFunction { k: RRsetKey?, v: RRSIGRecord? ->
                                sign(
                                    rrSet,
                                    dnskeyRecord,
                                    privateKey,
                                    inception,
                                    expiration
                                )
                            })
                    }
                }
            } catch (e: Exception) {
                val message = String.format(
                    "Failed to sign Resource Record Set for %s %d %d %d : %s",
                    dnskeyRecord.name, dnskeyRecord.dClass, dnskeyRecord.type, dnskeyRecord.ttl, e.message
                )
                ZoneSignerImpl.Companion.LOGGER.error(message, e)
            }
            if (signature != null) {
                signatures.add(signature)
            }
        })
        val signedRRset = RRset()
        toRRStream(rrSet).forEach(Consumer { r: Record? -> signedRRset.addRR(r) })
        signatures.forEach(Consumer { r: RRSIGRecord? -> signedRRset.addRR(r) })
        return signedRRset
    }

    private fun findSoaRecord(records: MutableList<Record?>?): SOARecord? {
        val soaRecordOptional = records.stream().filter { record: Record? -> record is SOARecord }.findFirst()
        return if (soaRecordOptional.isPresent) {
            soaRecordOptional.get() as SOARecord
        } else null
    }

    private fun createNsecRecords(records: MutableList<Record?>?): MutableList<NSECRecord?>? {
        val recordMap = records.stream().collect(Collectors.groupingBy { obj: Record? -> obj.getName() })
        val names = recordMap.keys.stream().sorted().collect(Collectors.toList())
        val nextNameTuples: MutableMap<Name?, Name?> = HashMap()
        for (i in names.indices) {
            val k = names[i]
            val v = names[(i + 1) % names.size]
            nextNameTuples[k] = v
        }
        val soaRecord = findSoaRecord(records)
        if (soaRecord == null) {
            ZoneSignerImpl.Companion.LOGGER.warn("No SOA record found, this extremely likely to produce DNSSEC errors")
        }
        val minimumSoaTtl = soaRecord?.minimum ?: 0L
        val nsecRecords: MutableList<NSECRecord?> = ArrayList()
        names.forEach(Consumer { name: Name? ->
            val mostTypes = recordMap[name].stream().mapToInt { obj: Record? -> obj.getType() }
                .toArray()
            val allTypes = IntArray(mostTypes.size + 2)
            System.arraycopy(mostTypes, 0, allTypes, 0, mostTypes.size)
            allTypes[mostTypes.size] = Type.NSEC
            allTypes[mostTypes.size + 1] = Type.RRSIG
            nsecRecords.add(NSECRecord(name, DClass.IN, minimumSoaTtl, nextNameTuples[name], allTypes))
        })
        return nsecRecords
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    override fun signZone(
        records: MutableList<Record?>?, kskPairs: MutableList<DnsSecKeyPair?>?,
        zskPairs: MutableList<DnsSecKeyPair?>?, inception: Date?, expiration: Date?,
        RRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>?
    ): MutableList<Record?>? {
        val nsecRecords = createNsecRecords(records)
        records.addAll(nsecRecords)
        Collections.sort(records) { record1: Record?, record2: Record? ->
            if (record1.getType() != Type.SOA && record2.getType() != Type.SOA) {
                return@sort record1.compareTo(record2)
            }
            var x = record1.getName().compareTo(record2.getName())
            if (x != 0) {
                return@sort x
            }
            x = record1.getDClass() - record2.getDClass()
            if (x != 0) {
                return@sort x
            }
            if (record1.getType() != record2.getType()) {
                return@sort if (record1.getType() == Type.SOA) -1 else 1
            }
            record1.compareTo(record2)
        }
        val rrSets = RRSetsBuilder().build(records)
        val signedRrSets = rrSets.stream()
            .map { rRset: RRset? -> signRRset(rRset, kskPairs, zskPairs, inception, expiration, RRSIGCache) }
            .sorted { rRset1: RRset?, rRset2: RRset? -> rRset1.getName().compareTo(rRset2.getName()) }
            .collect(Collectors.toList())
        val signedZoneRecords: MutableList<Record?> = ArrayList()
        signedRrSets.forEach(Consumer { rrSet: RRset? ->
            signedZoneRecords.addAll(toRRStream(rrSet).collect(Collectors.toList()))
            signedZoneRecords.addAll(toRRSigStream(rrSet).collect(Collectors.toList()))
        })
        return signedZoneRecords
    }

    override fun calculateDSRecord(dnskeyRecord: DNSKEYRecord?, digestId: Int, ttl: Long): DSRecord? {
        ZoneSignerImpl.Companion.LOGGER.info("Calculating DS Records for " + dnskeyRecord.getName())
        return DSRecord(dnskeyRecord.getName(), DClass.IN, ttl, digestId, dnskeyRecord)
    }

    companion object {
        private val LOGGER = Logger.getLogger(ZoneSignerImpl::class.java)
    }
}