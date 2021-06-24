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

import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignatureManager
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneManager.ZoneCacheType
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheRegister
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.comcast.cdn.traffic_control.traffic_router.core.util.ProtectedFetcher
import com.comcast.cdn.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import org.xbill.DNS.DSRecord
import org.xbill.DNS.Name
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.Record
import org.xbill.DNS.TextParseException
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.function.BiConsumer
import java.util.function.BinaryOperator
import java.util.function.Consumer
import java.util.function.Function

class SignatureManager(
    zoneManager: ZoneManager?,
    cacheRegister: CacheRegister?,
    trafficOpsUtils: TrafficOpsUtils?,
    private val trafficRouterManager: TrafficRouterManager?
) {
    private var expirationMultiplier = 0
    private var cacheRegister: CacheRegister? = null
    private var RRSIGCacheEnabled = false
    private var trafficOpsUtils: TrafficOpsUtils? = null
    private var dnssecEnabled = false
    private var expiredKeyAllowed = true
    private var keyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>? = null
    private var fetcher: ProtectedFetcher? = null
    private var zoneManager: ZoneManager? = null
    fun destroy() {
        if (SignatureManager.Companion.keyMaintenanceExecutor != null) {
            SignatureManager.Companion.keyMaintenanceExecutor.shutdownNow()
        }
    }

    private fun setRRSIGCacheEnabled(config: JsonNode?) {
        RRSIGCacheEnabled = JsonUtils.optBoolean(config, TrafficRouter.Companion.DNSSEC_RRSIG_CACHE_ENABLED, false)
        if (!RRSIGCacheEnabled) {
            synchronized(SignatureManager.Companion.RRSIGCacheLock) {
                SignatureManager.Companion.RRSIGCache =
                    ConcurrentHashMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>()
            }
        }
    }

    private fun isRRSIGCacheEnabled(): Boolean {
        return RRSIGCacheEnabled
    }

    private fun initKeyMap() {
        synchronized(SignatureManager::class.java) {
            val config = cacheRegister.getConfig()
            val dnssecEnabled: Boolean = optBoolean(config, TrafficRouter.Companion.DNSSEC_ENABLED)
            if (dnssecEnabled) {
                setDnssecEnabled(true)
                setExpiredKeyAllowed(
                    JsonUtils.optBoolean(
                        config,
                        "dnssec.allow.expired.keys",
                        true
                    )
                ) // allowing this by default is the safest option
                setExpirationMultiplier(
                    JsonUtils.optInt(
                        config,
                        "signaturemanager.expiration.multiplier",
                        5
                    )
                ) // signature validity is maxTTL * this
                val me = Executors.newScheduledThreadPool(1)
                val maintenanceInterval = JsonUtils.optInt(
                    config,
                    "keystore.maintenance.interval",
                    300
                ) // default 300 seconds, do we calculate based on the complimentary settings for key generation in TO?
                me.scheduleWithFixedDelay(
                    getKeyMaintenanceRunnable(cacheRegister),
                    0,
                    maintenanceInterval.toLong(),
                    TimeUnit.SECONDS
                )
                if (SignatureManager.Companion.keyMaintenanceExecutor != null) {
                    SignatureManager.Companion.keyMaintenanceExecutor.shutdownNow()
                }
                SignatureManager.Companion.keyMaintenanceExecutor = me
                try {
                    while (keyMap == null) {
                        SignatureManager.Companion.LOGGER.info("Waiting for DNSSEC keyMap initialization to complete")
                        Thread.sleep(2000)
                    }
                } catch (e: InterruptedException) {
                    SignatureManager.Companion.LOGGER.fatal(e, e)
                }
            } else {
                SignatureManager.Companion.LOGGER.info("DNSSEC not enabled; to enable, activate DNSSEC for this Traffic Router's CDN in Traffic Ops")
            }
        }
    }

    private fun getKeyMaintenanceRunnable(cacheRegister: CacheRegister?): Runnable? {
        return Runnable {
            try {
                trafficRouterManager.trackEvent("lastDnsSecKeysCheck")
                val newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?> = HashMap()
                val keyPairData = fetchKeyPairData(cacheRegister)
                if (keyPairData != null) {
                    val response = JsonUtils.getJsonNode(keyPairData, "response")
                    val dsIt: MutableIterator<*>? = response.fieldNames()
                    val config = cacheRegister.getConfig()
                    val defaultTTL = ZoneUtils.getLong(config["ttls"], "DNSKEY", 60)
                    while (dsIt.hasNext()) {
                        val keyTypes = JsonUtils.getJsonNode(response, dsIt.next() as String?)
                        val typeIt: MutableIterator<*>? = keyTypes.fieldNames()
                        while (typeIt.hasNext()) {
                            val keyPairs = JsonUtils.getJsonNode(keyTypes, typeIt.next() as String?)
                            if (keyPairs.isArray) {
                                for (keyPair in keyPairs) {
                                    try {
                                        val dkpw: DnsSecKeyPair = DnsSecKeyPairImpl(keyPair, defaultTTL)
                                        if (!newKeyMap.containsKey(dkpw.name)) {
                                            newKeyMap[dkpw.name] = ArrayList()
                                        }
                                        val keyList = newKeyMap[dkpw.name]
                                        keyList.add(dkpw)
                                        newKeyMap[dkpw.name] = keyList
                                        SignatureManager.Companion.LOGGER.debug("Added $dkpw to incoming keyList")
                                    } catch (ex: JsonUtilsException) {
                                        SignatureManager.Companion.LOGGER.fatal(
                                            "JsonUtilsException caught while parsing key for $keyPair",
                                            ex
                                        )
                                    } catch (ex: TextParseException) {
                                        SignatureManager.Companion.LOGGER.fatal(ex, ex)
                                    } catch (ex: IOException) {
                                        SignatureManager.Companion.LOGGER.fatal(ex, ex)
                                    }
                                }
                            }
                        }
                    }
                    cleanRRSIGCache(keyMap, newKeyMap)
                    if (keyMap == null) {
                        // initial startup
                        keyMap = newKeyMap
                    } else if (hasNewKeys(keyMap, newKeyMap)) {
                        // incoming key map has new keys
                        SignatureManager.Companion.LOGGER.debug("Found new keys in incoming keyMap; rebuilding zone caches")
                        trafficRouterManager.trackEvent("newDnsSecKeysFound")
                        keyMap = newKeyMap
                        getZoneManager().rebuildZoneCache()
                    } // no need to overwrite the keymap if they're the same, so no else leg
                } else {
                    SignatureManager.Companion.LOGGER.fatal("Unable to read keyPairData: $keyPairData")
                }
            } catch (ex: JsonUtilsException) {
                SignatureManager.Companion.LOGGER.fatal("JsonUtilsException caught while trying to maintain keyMap", ex)
            } catch (ex: RuntimeException) {
                SignatureManager.Companion.LOGGER.fatal("RuntimeException caught while trying to maintain keyMap", ex)
            }
        }
    }

    private fun cleanRRSIGCache(
        oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?,
        newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?
    ) {
        synchronized(SignatureManager.Companion.RRSIGCacheLock) {
            if (SignatureManager.Companion.RRSIGCache.isEmpty() || oldKeyMap == null || getKeyDifferences(
                    oldKeyMap,
                    newKeyMap
                ).isEmpty()
            ) {
                return
            }
            val oldKeySize: Int = SignatureManager.Companion.RRSIGCache.size
            val oldRRSIGSize: Int = SignatureManager.Companion.RRSIGCache.values.stream()
                .map<Int?>(Function { obj: ConcurrentMap<RRsetKey?, RRSIGRecord?>? -> obj.size })
                .reduce(0, BinaryOperator { a: Int, b: Int -> Integer.sum(a, b) })
            val now = Date().time
            val newRRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?> =
                ConcurrentHashMap()
            newKeyMap.forEach(BiConsumer { name: String?, keyPairs: MutableList<DnsSecKeyPair?>? ->
                keyPairs.forEach(
                    Consumer { keypair: DnsSecKeyPair? ->
                        val cacheKey = RRSIGCacheKey(keypair.getPrivate().encoded, keypair.getDNSKEYRecord().algorithm)
                        val cacheValue: ConcurrentMap<RRsetKey?, RRSIGRecord?> =
                            SignatureManager.Companion.RRSIGCache.get(cacheKey)
                        if (cacheValue != null) {
                            cacheValue.entries.removeIf { e: MutableMap.MutableEntry<RRsetKey?, RRSIGRecord?>? -> e.value.getExpire().time <= now }
                            newRRSIGCache[cacheKey] = cacheValue
                        }
                    })
            })
            SignatureManager.Companion.RRSIGCache = newRRSIGCache
            val keySize: Int = SignatureManager.Companion.RRSIGCache.size
            val RRSIGSize: Int = SignatureManager.Companion.RRSIGCache.values.stream()
                .map<Int?>(Function { obj: ConcurrentMap<RRsetKey?, RRSIGRecord?>? -> obj.size })
                .reduce(0, BinaryOperator { a: Int, b: Int -> Integer.sum(a, b) })
            SignatureManager.Companion.LOGGER.info(
                "DNSSEC keys were changed or removed so RRSIG cache was cleaned. Old key size: " + oldKeySize +
                        ", new key size: " + keySize + ", old RRSIG size: " + oldRRSIGSize + ", new RRSIG size: " + RRSIGSize
            )
        }
    }

    // return the key names from newKeyMap that are different or missing from oldKeyMap
    private fun getKeyDifferences(
        newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?,
        oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?
    ): MutableSet<String?>? {
        val newKeyNames: MutableSet<String?> = HashSet()
        for (newName in newKeyMap.keys) {
            if (!oldKeyMap.containsKey(newName)) {
                newKeyNames.add(newName)
                continue
            }
            for (newKeyPair in newKeyMap.get(newName)) {
                var matched = false
                for (keyPair in oldKeyMap.get(newName)) {
                    if (newKeyPair == keyPair) {
                        matched = true
                        break
                    }
                }
                if (!matched) {
                    newKeyNames.add(newKeyPair.getName())
                    break
                }
            }
        }
        return newKeyNames
    }

    private fun hasNewKeys(
        oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?,
        newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?
    ): Boolean {
        val newOrChangedKeyNames = getKeyDifferences(newKeyMap, oldKeyMap)
        if (!newOrChangedKeyNames.isEmpty()) {
            newOrChangedKeyNames.forEach(Consumer { name: String? ->
                SignatureManager.Companion.LOGGER.info(
                    "Found new or changed key for $name"
                )
            })
            return true
        }
        return false
    }

    private fun fetchKeyPairData(cacheRegister: CacheRegister?): JsonNode? {
        if (!isDnssecEnabled()) {
            return null
        }
        var keyPairs: JsonNode? = null
        val mapper = ObjectMapper()
        try {
            val keyUrl = trafficOpsUtils.getUrl(
                "keystore.api.url",
                "https://\${toHostname}/api/2.0/cdns/name/\${cdnName}/dnsseckeys"
            )
            val config = cacheRegister.getConfig()
            val timeout = JsonUtils.optInt(config, "keystore.fetch.timeout", 30000) // socket timeouts are in ms
            val retries = JsonUtils.optInt(config, "keystore.fetch.retries", 5)
            val wait = JsonUtils.optInt(config, "keystore.fetch.wait", 5000) // 5 seconds
            if (fetcher == null) {
                fetcher =
                    ProtectedFetcher(trafficOpsUtils.getAuthUrl(), trafficOpsUtils.getAuthJSON().toString(), timeout)
            }
            for (i in 1..retries) {
                try {
                    val content = fetcher.fetch(keyUrl)
                    if (content != null) {
                        keyPairs = mapper.readTree(content)
                        break
                    }
                } catch (ex: IOException) {
                    SignatureManager.Companion.LOGGER.fatal(ex, ex)
                }
                try {
                    Thread.sleep(wait.toLong())
                } catch (ex: InterruptedException) {
                    SignatureManager.Companion.LOGGER.fatal(ex, ex)
                    // break if we're interrupted
                    break
                }
            }
        } catch (ex: IOException) {
            SignatureManager.Companion.LOGGER.fatal(ex, ex)
        }
        return keyPairs
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getZoneSigningKSKPair(name: Name?, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        return getZoneSigningKeyPair(name, true, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getZoneSigningZSKPair(name: Name?, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        return getZoneSigningKeyPair(name, false, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getZoneSigningKeyPair(name: Name?, wantKsk: Boolean, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        /*
		 * This method returns a list, but we will identify the correct key with which to sign the zone.
		 * We select one key (we call this method twice, for zsk and ksks respectively)
		 * to follow the pre-publish key roll methodology described in RFC 6781.
		 * https://tools.ietf.org/html/rfc6781#section-4.1.1.1
		 */
        return getKeyPairs(name, wantKsk, true, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getKSKPairs(name: Name?, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        return getKeyPairs(name, true, false, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getZSKPairs(name: Name?, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        return getKeyPairs(name, false, false, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getKeyPairs(
        name: Name?,
        wantKsk: Boolean,
        wantSigningKey: Boolean,
        maxTTL: Long
    ): MutableList<DnsSecKeyPair?>? {
        val keyPairs = keyMap.get(name.toString().toLowerCase())
        var signingKey: DnsSecKeyPair? = null
        if (keyPairs == null) {
            return null
        }
        val keys: MutableList<DnsSecKeyPair?> = ArrayList()
        for (kpw in keyPairs) {
            val kn = kpw.getDNSKEYRecord().name
            val isKsk = kpw.isKeySigningKey()
            if (kn == name) {
                if (isKsk && !wantKsk || !isKsk && wantKsk) {
                    SignatureManager.Companion.LOGGER.debug("Skipping key: wantKsk = " + wantKsk + "; key: " + kpw.toString())
                    continue
                } else if (!wantSigningKey && (isExpiredKeyAllowed() || kpw.isKeyCached(maxTTL))) {
                    SignatureManager.Companion.LOGGER.debug("key selected: " + kpw.toString())
                    keys.add(kpw)
                } else if (wantSigningKey) {
                    if (!kpw.isUsable()) { // effective date in the future
                        SignatureManager.Companion.LOGGER.debug("Skipping unusable signing key: " + kpw.toString())
                        continue
                    } else if (!isExpiredKeyAllowed() && kpw.isExpired()) {
                        SignatureManager.Companion.LOGGER.warn("Unable to use expired signing key: " + kpw.toString())
                        continue
                    }

                    // Locate the key with the earliest valid effective date accounting for expiration
                    if (isKsk && wantKsk || !isKsk && !wantKsk) {
                        if (signingKey == null) {
                            signingKey = kpw
                        } else if (signingKey.isExpired && !kpw.isExpired()) {
                            signingKey = kpw
                        } else if (signingKey.isExpired && kpw.isNewer(signingKey)) {
                            signingKey = kpw // if we have an expired key, try to find the most recent
                        } else if (!signingKey.isExpired && !kpw.isExpired() && kpw.isOlder(signingKey)) {
                            signingKey = kpw // otherwise use the oldest valid/non-expired key
                        }
                    }
                }
            } else {
                SignatureManager.Companion.LOGGER.warn("Invalid key for " + name + "; it is intended for " + kpw.toString())
            }
        }
        if (wantSigningKey && signingKey != null) {
            if (signingKey.isExpired) {
                SignatureManager.Companion.LOGGER.warn("Using expired signing key: $signingKey")
            } else {
                SignatureManager.Companion.LOGGER.debug("Signing key selected: $signingKey")
            }
            keys.clear() // in case we have something in here for some reason (shouldn't happen)
            keys.add(signingKey)
        } else if (wantSigningKey && signingKey == null) {
            SignatureManager.Companion.LOGGER.fatal("Unable to find signing key for $name")
        }
        return keys
    }

    private fun calculateKeyExpiration(keyPairs: MutableList<DnsSecKeyPair?>?): Calendar? {
        val expiration = Calendar.getInstance()
        var earliest: Date? = null
        for (keyPair in keyPairs) {
            if (earliest == null) {
                earliest = keyPair.getExpiration()
            } else if (keyPair.getExpiration().before(earliest)) {
                earliest = keyPair.getExpiration()
            }
        }
        expiration.time = earliest
        return expiration
    }

    private fun calculateSignatureExpiration(baseTimeInMillis: Long, records: MutableList<Record?>?): Calendar? {
        val expiration = Calendar.getInstance()
        val maxTTL = ZoneUtils.getMaximumTTL(records) * 1000 // convert TTL to millis
        val signatureExpiration = baseTimeInMillis + maxTTL * getExpirationMultiplier()
        expiration.timeInMillis = signatureExpiration
        return expiration
    }

    fun needsRefresh(type: ZoneCacheType?, zoneKey: ZoneKey?, refreshInterval: Int): Boolean {
        return if (zoneKey is SignedZoneKey) {
            val szk = zoneKey as SignedZoneKey?
            val now = System.currentTimeMillis()
            val nextRefresh = now + refreshInterval * 1000 // refreshInterval is in seconds, convert to millis
            if (nextRefresh >= szk.getRefreshHorizon()) {
                SignatureManager.Companion.LOGGER.info(
                    getRefreshMessage(
                        type,
                        szk,
                        true,
                        "refresh horizon approaching"
                    )
                )
                true
            } else if (!isExpiredKeyAllowed() && now >= szk.getEarliestSigningKeyExpiration()) {
                /*
				 * The earliest signing key has expired, so force a resigning
				 * which will be done with new keys. This is because the keys themselves
				 * don't have expiry that's tied to DNSSEC; it's administrative, so
				 * we can be a little late on the swap.
				 */
                SignatureManager.Companion.LOGGER.info(getRefreshMessage(type, szk, true, "signing key expiration"))
                true
            } else {
                SignatureManager.Companion.LOGGER.debug(getRefreshMessage(type, szk))
                false
            }
        } else {
            SignatureManager.Companion.LOGGER.debug(type.toString() + ": " + zoneKey.getName() + " is not a signed zone; no refresh needed")
            false
        }
    }

    private fun getRefreshMessage(type: ZoneCacheType?, zoneKey: SignedZoneKey?): String? {
        return getRefreshMessage(type, zoneKey, false, null)
    }

    private fun getRefreshMessage(
        type: ZoneCacheType?,
        zoneKey: SignedZoneKey?,
        needsRefresh: Boolean,
        message: String?
    ): String? {
        val sb = StringBuilder()
        sb.append(type)
        sb.append(": timestamp for ")
        sb.append(zoneKey.getName())
        sb.append(" is ")
        sb.append(zoneKey.getTimestampDate())
        sb.append("; expires ")
        sb.append(zoneKey.getMinimumSignatureExpiration().time)
        if (needsRefresh) {
            sb.append("; refresh needed")
        } else {
            sb.append("; no refresh needed")
        }
        if (message != null) {
            sb.append("; ")
            sb.append(message)
        }
        return sb.toString()
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    fun signZone(name: Name?, records: MutableList<Record?>?, zoneKey: SignedZoneKey?): MutableList<Record?>? {
        val maxTTL = ZoneUtils.getMaximumTTL(records)
        val kskPairs = getZoneSigningKSKPair(name, maxTTL)
        val zskPairs = getZoneSigningZSKPair(name, maxTTL)

        // TODO: do we really need to fully sign the apex keyset? should the digest be config driven?
        if (kskPairs != null && zskPairs != null) {
            if (!kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                val signatureExpiration = calculateSignatureExpiration(zoneKey.getTimestamp(), records)
                val kskExpiration = calculateKeyExpiration(kskPairs)
                val zskExpiration = calculateKeyExpiration(zskPairs)
                val now = System.currentTimeMillis()
                val start = Calendar.getInstance()
                start.timeInMillis = now
                start.add(Calendar.HOUR, -1)
                SignatureManager.Companion.LOGGER.info("Signing zone " + name + " with start " + start.time + " and expiration " + signatureExpiration.getTime())
                val signedRecords: MutableList<Record?>
                val zoneSigner: ZoneSigner = ZoneSignerImpl()
                signedRecords = zoneSigner.signZone(
                    records,
                    kskPairs,
                    zskPairs,
                    start.time,
                    signatureExpiration.getTime(),
                    if (isRRSIGCacheEnabled()) SignatureManager.Companion.RRSIGCache else null
                )
                zoneKey.setMinimumSignatureExpiration(signedRecords, signatureExpiration)
                zoneKey.setKSKExpiration(kskExpiration)
                zoneKey.setZSKExpiration(zskExpiration)
                return signedRecords
            } else {
                SignatureManager.Companion.LOGGER.warn("Unable to sign zone " + name + "; have " + kskPairs.size + " KSKs and " + zskPairs.size + " ZSKs")
            }
        } else {
            SignatureManager.Companion.LOGGER.warn("Unable to sign zone $name; ksks or zsks are null")
        }
        return records
    }

    @Throws(NoSuchAlgorithmException::class, IOException::class)
    fun generateDSRecords(name: Name?, maxTTL: Long): MutableList<Record?>? {
        val records: MutableList<Record?> = ArrayList()
        if (isDnssecEnabled() && name.subdomain(ZoneManager.Companion.getTopLevelDomain())) {
            val config = getCacheRegister().getConfig()
            val kskPairs = getKSKPairs(name, maxTTL)
            val zskPairs = getZSKPairs(name, maxTTL)
            if (kskPairs != null && zskPairs != null && !kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                // these records go into the CDN TLD, so don't use the DS' TTLs; use the CDN's.
                val dsTtl = ZoneUtils.getLong(config["ttls"], "DS", 60)
                for (kp in kskPairs) {
                    val zoneSigner: ZoneSigner = ZoneSignerImpl()
                    val dsRecord = zoneSigner.calculateDSRecord(kp.getDNSKEYRecord(), DSRecord.SHA256_DIGEST_ID, dsTtl)
                    SignatureManager.Companion.LOGGER.debug(name.toString() + ": adding DS record " + dsRecord)
                    records.add(dsRecord)
                }
            }
        }
        return records
    }

    @Throws(NoSuchAlgorithmException::class, IOException::class)
    fun generateDNSKEYRecords(name: Name?, maxTTL: Long): MutableList<Record?>? {
        val list: MutableList<Record?> = ArrayList()
        if (isDnssecEnabled() && name.subdomain(ZoneManager.Companion.getTopLevelDomain())) {
            val kskPairs = getKSKPairs(name, maxTTL)
            val zskPairs = getZSKPairs(name, maxTTL)
            if (kskPairs != null && zskPairs != null && !kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                for (kp in kskPairs) {
                    SignatureManager.Companion.LOGGER.debug(name.toString() + ": DNSKEY record " + kp.getDNSKEYRecord())
                    list.add(kp.getDNSKEYRecord())
                }
                for (kp in zskPairs) {
                    // TODO: make adding zsk to parent zone configurable?
                    SignatureManager.Companion.LOGGER.debug(name.toString() + ": DNSKEY record " + kp.getDNSKEYRecord())
                    list.add(kp.getDNSKEYRecord())
                }
            }
        }
        return list
    }

    // this method is called during static zone generation
    fun generateZoneKey(name: Name?, list: MutableList<Record?>?): ZoneKey? {
        return generateZoneKey(name, list, false, false)
    }

    fun generateDynamicZoneKey(name: Name?, list: MutableList<Record?>?, dnssecRequest: Boolean): ZoneKey? {
        return generateZoneKey(name, list, true, dnssecRequest)
    }

    private fun generateZoneKey(
        name: Name?,
        list: MutableList<Record?>?,
        dynamicRequest: Boolean,
        dnssecRequest: Boolean
    ): ZoneKey? {
        return if (dynamicRequest && !dnssecRequest) {
            ZoneKey(name, list)
        } else if (isDnssecEnabled(name) && name.subdomain(ZoneManager.Companion.getTopLevelDomain())) {
            SignedZoneKey(name, list)
        } else {
            ZoneKey(name, list)
        }
    }

    fun isDnssecEnabled(): Boolean {
        return dnssecEnabled
    }

    private fun isDnssecEnabled(name: Name?): Boolean {
        return dnssecEnabled && keyMap.containsKey(name.toString().toLowerCase())
    }

    private fun setDnssecEnabled(dnssecEnabled: Boolean) {
        this.dnssecEnabled = dnssecEnabled
    }

    protected fun getCacheRegister(): CacheRegister? {
        return cacheRegister
    }

    private fun setCacheRegister(cacheRegister: CacheRegister?) {
        this.cacheRegister = cacheRegister
    }

    fun getExpirationMultiplier(): Int {
        return expirationMultiplier
    }

    fun setExpirationMultiplier(expirationMultiplier: Int) {
        this.expirationMultiplier = expirationMultiplier
    }

    private fun getZoneManager(): ZoneManager? {
        return zoneManager
    }

    private fun setZoneManager(zoneManager: ZoneManager?) {
        this.zoneManager = zoneManager
    }

    private fun setTrafficOpsUtils(trafficOpsUtils: TrafficOpsUtils?) {
        this.trafficOpsUtils = trafficOpsUtils
    }

    fun isExpiredKeyAllowed(): Boolean {
        return expiredKeyAllowed
    }

    fun setExpiredKeyAllowed(expiredKeyAllowed: Boolean) {
        this.expiredKeyAllowed = expiredKeyAllowed
    }

    companion object {
        private val LOGGER = Logger.getLogger(SignatureManager::class.java)
        private val RRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>? =
            ConcurrentHashMap()
        private val RRSIGCacheLock: Any? = Any() // to ensure that the RRSIGCache is totally empty if disabled
        private val keyMaintenanceExecutor: ScheduledExecutorService? = null
    }

    init {
        setCacheRegister(cacheRegister)
        setTrafficOpsUtils(trafficOpsUtils)
        setZoneManager(zoneManager)
        setRRSIGCacheEnabled(cacheRegister.getConfig())
        initKeyMap()
    }
}