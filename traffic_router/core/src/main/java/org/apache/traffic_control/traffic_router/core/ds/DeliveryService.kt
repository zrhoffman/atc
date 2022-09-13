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
package org.apache.traffic_control.traffic_router.core.ds

import com.fasterxml.jackson.annotation.JsonIgnoreimport

com.fasterxml.jackson.databind.JsonNodeimport org.apache.traffic_control.traffic_router.core.request.DNSRequestimport org.apache.traffic_control.traffic_router.core.request.HTTPRequestimport org.apache.traffic_control.traffic_router.core.router.StatTrackerimport org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetailsimport org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultTypeimport org.apache.traffic_control.traffic_router.core.util.*import org.apache.traffic_control.traffic_router.geolocation.Geolocationimport

java.security.GeneralSecurityExceptionimport java.util.*import java.util.concurrent.atomic.AtomicInteger

org.apache.logging.log4j.LogManager
import org.apache.tomcat.util.net.SSLImplementation
import org.apache.tomcat.util.net.SSLSupport
import org.apache.tomcat.util.net.jsse.JSSESupport
import org.apache.tomcat.util.net.SSLUtilimport

org.apache.traffic_control.traffic_router.core.edge.*import org.apache.traffic_control.traffic_router.core.util.*
import secure.KeyManagerTest.TestSNIServerName
import secure.CertificateDataConverterTest
import org.apache.traffic_control.traffic_router.protocol.RouterSslImplementationimport

java.io.*import java.lang.Exceptionimport

java.net.*import java.util.ArrayListimport

java.util.function.Consumerimport java.util.regex.Pattern
class DeliveryService(private val id: String?, @field:JsonIgnore private val props: JsonNode?) {
    @JsonIgnore
    private val ttls: JsonNode?
    private val coverageZoneOnly: Boolean

    @JsonIgnore
    private val geoEnabled: JsonNode?
    private val geoRedirectUrl: String?

    //store the url file path info
    private var geoRedirectFile: String?

    //check if the geoRedirectUrl belongs to this DeliveryService, avoid calculating this for multiple times
    //"INVALID_URL" for init status, "DS_URL" means that the request url belongs to this DeliveryService, "NOT_DS_URL" means that the request url doesn't belong to this DeliveryService
    private var geoRedirectUrlType: String?

    @JsonIgnore
    private val staticDnsEntries: JsonNode?

    @JsonIgnore
    private val domain: String?

    @JsonIgnore
    private val tld: String?

    @JsonIgnore // Matches the beginning of a HOST_REGEXP pattern with or without confighandler.regex.superhack.enabled.
    // ^\(\.\*\\\.\|\^\)|^\.\*\\\.|\\\.\.\*

    private val wildcardPattern = Pattern.compile("^\\(\\.\\*\\\\\\.\\|\\^\\)|^\\.\\*\\\\\\.|\\\\\\.\\.\\*")

    @JsonIgnore
    private val bypassDestination: JsonNode?

    @JsonIgnore
    private val soa: JsonNode?
    private var isDns = false
    private val routingName: String?
    private var topology: String? = null
    private val requiredCapabilities: MutableSet<String?>?
    private val shouldAppendQueryString: Boolean
    private val missLocation: Geolocation?
    private val dispersion: Dispersion?
    private val ip6RoutingEnabled: Boolean
    private val responseHeaders: MutableMap<String?, String?>? = HashMap()
    private val requestHeaders: MutableSet<String?>? = HashSet()
    private val regionalGeoEnabled: Boolean
    private val geolocationProvider: String?
    private val anonymousIpEnabled: Boolean
    private val sslEnabled: Boolean
    private var hasX509Cert = false
    private val acceptHttp: Boolean
    private val acceptHttps: Boolean
    private val redirectToHttps: Boolean
    private val deepCache: DeepCachingType? = null
    private var consistentHashRegex: String?
    private val consistentHashQueryParams: MutableSet<String?>?
    private var ecsEnabled: Boolean

    enum class DeepCachingType {
        NEVER, ALWAYS
    }

    private fun initRequiredCapabilities(dsJo: JsonNode?) {
        if (dsJo.has("requiredCapabilities")) {
            val requiredCapabilitiesNode = dsJo.get("requiredCapabilities")
            if (!requiredCapabilitiesNode.isArray) {
                LOGGER.error("Delivery Service '$id' has malformed requiredCapabilities. Disregarding.")
            } else {
                requiredCapabilitiesNode.forEach(Consumer { requiredCapabilityNode: JsonNode? ->
                    val requiredCapability = requiredCapabilityNode.asText()
                    if (!requiredCapability.isEmpty()) {
                        requiredCapabilities.add(requiredCapability)
                    }
                })
            }
        }
    }

    private fun initConsistentHashQueryParams(dsJo: JsonNode?) {
        if (dsJo.has("consistentHashQueryParams")) {
            val cqpNode = dsJo.get("consistentHashQueryParams")
            if (!cqpNode.isArray) {
                LOGGER.error("Delivery Service '$id' has malformed consistentHashQueryParams. Disregarding.")
            } else {
                for (n in cqpNode) {
                    val s = n.asText()
                    if (!s.isEmpty()) {
                        consistentHashQueryParams.add(s)
                    }
                }
            }
        }
    }

    private fun initTopology(dsJo: JsonNode?) {
        if (dsJo.has("topology")) {
            topology = optString(dsJo, "topology")
        }
    }

    private fun initMissLocation(mlJo: JsonNode?): Geolocation? {
        return if (mlJo != null) {
            val lat: Double = optDouble(mlJo, "lat")
            val longitude: Double = optDouble(mlJo, "long")
            Geolocation(lat, longitude)
        } else {
            null
        }
    }

    private fun getDomainFromJson(domains: JsonNode?): String? {
        return domains?.get(0)?.asText()
    }

    fun getConsistentHashQueryParams(): MutableSet<String?>? {
        return consistentHashQueryParams
    }

    fun getId(): String? {
        return id
    }

    @JsonIgnore
    fun getTtls(): JsonNode? {
        return ttls
    }

    override fun toString(): String {
        return "DeliveryService [id=$id]"
    }

    fun getMissLocation(): Geolocation? {
        return missLocation
    }

    fun supportLocation(clientLocation: Geolocation?): Geolocation? {
        if (clientLocation == null) {
            return missLocation
        }
        return if (isLocationBlocked(clientLocation)) {
            null
        } else clientLocation
    }

    private fun isLocationBlocked(clientLocation: Geolocation?): Boolean {
        if (geoEnabled == null || geoEnabled.size() == 0) {
            return false
        }
        val locData = clientLocation.getProperties()
        for (constraint in geoEnabled) {
            var match = true
            try {
                val keyIter = constraint.fieldNames()
                while (keyIter.hasNext()) {
                    val t = keyIter.next()
                    val v = JsonUtils.getString(constraint, t)
                    val data = locData[t]
                    if (!v.equals(data, ignoreCase = true)) {
                        match = false
                        break
                    }
                }
                if (match) {
                    return false
                }
            } catch (ex: JsonUtilsException) {
                LOGGER.warn(ex, ex)
            }
        }
        return true
    }

    fun isCoverageZoneOnly(): Boolean {
        return coverageZoneOnly
    }

    @Throws(MalformedURLException::class)
    fun getFailureHttpResponse(request: HTTPRequest?, track: StatTracker.Track?): URL? {
        if (bypassDestination == null) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_NO_BYPASS)
            return null
        }
        track.setResult(ResultType.DS_REDIRECT)
        val httpJo = bypassDestination["HTTP"]
        if (httpJo == null) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_NO_BYPASS)
            return null
        }
        val fqdn = httpJo["fqdn"]
        if (fqdn == null) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_NO_BYPASS)
            return null
        }
        var port = if (request.isSecure()) 443 else 80
        if (httpJo.has("port")) {
            port = httpJo["port"].asInt()
        }
        return URL(createURIString(request, fqdn.asText(), port, null))
    }

    private fun useSecure(request: HTTPRequest?): Boolean {
        return if (request.isSecure()) {
            acceptHttps && isSslReady()
        } else redirectToHttps && acceptHttps && isSslReady()
    }

    private fun getPortString(request: HTTPRequest?, port: Int): String? {
        val standard_port = if (useSecure(request)) STANDARD_HTTPS_PORT else STANDARD_HTTP_PORT
        return if (port == standard_port) "" else ":$port"
    }

    private fun getPortString(request: HTTPRequest?, cache: Cache?): String? {
        val cache_port = if (useSecure(request)) cache.getHttpsPort() else cache.getPort()
        return getPortString(request, cache_port)
    }

    fun createURIString(request: HTTPRequest?, cache: Cache?): String? {
        var fqdn = getFQDN(cache)
        if (fqdn == null) {
            val cacheName: Array<String?> = cache.getFqdn().split(REGEX_PERIOD.toRegex(), limit = 2).toTypedArray()
            fqdn = cacheName[0] + "." + request.getHostname().split(REGEX_PERIOD.toRegex(), limit = 2).toTypedArray()[1]
        }
        val port = if (useSecure(request)) cache.getHttpsPort() else cache.getPort()
        return createURIString(request, fqdn, port, getTransInfoStr(request))
    }

    private fun createURIString(request: HTTPRequest?, fqdn: String?, port: Int, tinfo: String?): String? {
        val uri = StringBuilder(if (useSecure(request)) "https://" else "http://")
        uri.append(fqdn)
        uri.append(getPortString(request, port))
        uri.append(request.getUri())
        var queryAppended = false
        if (request.getQueryString() != null && appendQueryString()) {
            uri.append('?').append(request.getQueryString())
            queryAppended = true
        }
        if (tinfo != null) {
            if (queryAppended) {
                uri.append('&')
            } else {
                uri.append('?')
            }
            uri.append(tinfo)
        }
        return uri.toString()
    }

    fun createURIString(request: HTTPRequest?, alternatePath: String?, cache: Cache?): String? {
        val uri = StringBuilder(if (useSecure(request)) "https://" else "http://")
        var fqdn = getFQDN(cache)
        if (fqdn == null) {
            val cacheName: Array<String?> = cache.getFqdn().split(REGEX_PERIOD.toRegex(), limit = 2).toTypedArray()
            fqdn = cacheName[0] + "." + request.getHostname().split(REGEX_PERIOD.toRegex(), limit = 2).toTypedArray()[1]
        }
        uri.append(fqdn)
        uri.append(getPortString(request, cache))
        uri.append(alternatePath)
        return uri.toString()
    }

    fun getRemap(dsPattern: String?): String? {
        if (!dsPattern.contains(".*")) {
            return dsPattern
        }
        val host = wildcardPattern.matcher(dsPattern).replaceAll("") + "." + tld
        return if (isDns()) routingName + "." + host else host
    }

    private fun getFQDN(cache: Cache?): String? {
        for (dsRef in cache.getDeliveryServices()) {
            if (dsRef.deliveryServiceId == getId()) {
                return dsRef.fqdn
            }
        }
        return null
    }

    fun getFailureDnsResponse(request: DNSRequest?, track: StatTracker.Track?): MutableList<InetRecord?>? {
        if (bypassDestination == null) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_NO_BYPASS)
            return null
        }
        track.setResult(ResultType.DS_REDIRECT)
        track.setResultDetails(ResultDetails.DS_BYPASS)
        return getRedirectInetRecords(bypassDestination["DNS"])
    }

    private var redirectInetRecords: MutableList<InetRecord?>? = null
    private fun getRedirectInetRecords(dns: JsonNode?): MutableList<InetRecord?>? {
        if (dns == null) {
            return null
        }
        if (redirectInetRecords != null) {
            return redirectInetRecords
        }
        try {
            synchronized(this) {
                val list: MutableList<InetRecord?> = ArrayList()
                val ttl = dns["ttl"].asInt() // we require a TTL to exist; will throw an exception if not present
                if (dns.has("ip") || dns.has("ip6")) {
                    if (dns.has("ip")) {
                        list.add(InetRecord(InetAddress.getByName(dns["ip"].asText()), ttl.toLong()))
                    }
                    if (dns.has("ip6")) {
                        var ipStr = dns["ip6"].asText()
                        if (ipStr != null && !ipStr.isEmpty()) {
                            ipStr = ipStr.replace("/.*".toRegex(), "")
                            list.add(InetRecord(InetAddress.getByName(ipStr), ttl.toLong()))
                        }
                    }
                } else if (dns.has("cname")) {
                    /*
					 * Per section 2.4 of RFC 1912 CNAMEs cannot coexist with other record types.
					 * As such, only add the CNAME if the above ip/ip6 keys do not exist
					 */
                    val cname = dns["cname"].asText()
                    if (cname != null) {
                        list.add(InetRecord(cname, ttl.toLong()))
                    }
                }
                redirectInetRecords = list
            }
        } catch (e: Exception) {
            redirectInetRecords = null
            LOGGER.warn(e, e)
        }
        return redirectInetRecords
    }

    @JsonIgnore
    fun getSoa(): JsonNode? {
        return soa
    }

    fun isDns(): Boolean {
        return isDns
    }

    fun setDns(isDns: Boolean) {
        this.isDns = isDns
    }

    fun getDeepCache(): DeepCachingType? {
        return deepCache
    }

    fun appendQueryString(): Boolean {
        return shouldAppendQueryString
    }

    internal enum class TransInfoType {
        NONE, IP, IP_TID
    }

    fun getTransInfoStr(request: HTTPRequest?): String? {
        val type = TransInfoType.valueOf(getProp("transInfoType", "NONE"))
        if (type == TransInfoType.NONE) {
            return null
        }
        try {
            val ipBytes = getClientIpBytes(request, type) ?: return null
            return getEncryptedTrans(type, ipBytes)
        } catch (e: Exception) {
            LOGGER.warn(e, e)
        }
        return null
    }

    @Throws(UnknownHostException::class)
    private fun getClientIpBytes(request: HTTPRequest?, type: TransInfoType?): ByteArray? {
        val ip = InetAddress.getByName(request.getClientIP())
        var ipBytes = ip.address
        if (ipBytes.size > 4) {
            if (type == TransInfoType.IP) {
                return null
            }
            ipBytes = byteArrayOf(0, 0, 0, 0)
        }
        return ipBytes
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    private fun getEncryptedTrans(type: TransInfoType?, ipBytes: ByteArray?): String? {
        ByteArrayOutputStream().use { baos ->
            DataOutputStream(baos).use { dos ->
                dos.write(ipBytes)
                if (type == TransInfoType.IP_TID) {
                    dos.writeLong(System.currentTimeMillis())
                    dos.writeInt(getTid())
                }
                dos.flush()
                return "t0=" + getStringProtector().encryptForUrl(baos.toByteArray())
            }
        }
    }

    private fun getProp(key: String?, d: String?): String? {
        return if (props == null || !props.has(key)) {
            d
        } else props[key].textValue()
    }

    private fun getProp(key: String?, d: Int): Int {
        return if (props == null || !props.has(key)) {
            d
        } else props[key].asInt()
    }

    private var isAvailable = true
    private var disabledLocations: JsonNode? = null

    init {
        ttls = props.get("ttls")
        if (ttls == null) {
            LOGGER.warn("ttls is null for:$id")
        }
        coverageZoneOnly = JsonUtils.getBoolean(props, "coverageZoneOnly")
        geoEnabled = props.get("geoEnabled")
        var rurl = JsonUtils.optString(props, "geoLimitRedirectURL", null)
        if (rurl != null && rurl.isEmpty()) {
            rurl = null
        }
        geoRedirectUrl = rurl
        geoRedirectUrlType = "INVALID_URL"
        geoRedirectFile = geoRedirectUrl
        staticDnsEntries = props.get("staticDnsEntries")
        bypassDestination = props.get("bypassDestination")
        routingName = JsonUtils.getString(props, "routingName").lowercase(Locale.getDefault())
        domain = getDomainFromJson(props.get("domains"))
        tld = if (domain != null) domain.replace("^.*?\\.".toRegex(), "") else null
        soa = props.get("soa")
        shouldAppendQueryString = JsonUtils.optBoolean(props, "appendQueryString", true)
        ecsEnabled = optBoolean(props, "ecsEnabled")
        initTopology(props)
        requiredCapabilities = HashSet()
        initRequiredCapabilities(props)
        consistentHashQueryParams = HashSet()
        initConsistentHashQueryParams(props)

        // missLocation: {lat: , long: }
        val mlJo = props.get("missLocation")
        missLocation = initMissLocation(mlJo)
        dispersion = Dispersion(props)
        ip6RoutingEnabled = optBoolean(props, "ip6RoutingEnabled")
        setResponseHeaders(props.get("responseHeaders"))
        setRequestHeaders(props.get("requestHeaders"))
        regionalGeoEnabled = optBoolean(props, "regionalGeoBlocking")
        geolocationProvider = optString(props, "geolocationProvider")
        if (geolocationProvider != null && !geolocationProvider.isEmpty()) {
            LOGGER.info("DeliveryService '$id' has configured geolocation provider '$geolocationProvider'")
        } else {
            LOGGER.info("DeliveryService '$id' will use default geolocation provider Maxmind")
        }
        sslEnabled = optBoolean(props, "sslEnabled")
        anonymousIpEnabled = optBoolean(props, "anonymousBlockingEnabled")
        consistentHashRegex = optString(props, "consistentHashRegex")
        val protocol = props.get("protocol")
        acceptHttp = JsonUtils.optBoolean(protocol, "acceptHttp", true)
        acceptHttps = optBoolean(protocol, "acceptHttps")
        redirectToHttps = optBoolean(protocol, "redirectToHttps")
        val dctString = JsonUtils.optString(props, "deepCachingType", "NEVER").uppercase(Locale.getDefault())
        var dct = DeepCachingType.NEVER
        try {
            dct = DeepCachingType.valueOf(dctString)
        } catch (e: IllegalArgumentException) {
            LOGGER.error("DeliveryService '$id' has an unrecognized deepCachingType: '$dctString'. Defaulting to 'NEVER' instead")
        } finally {
            deepCache = dct
        }
    }

    fun setState(state: JsonNode?) {
        isAvailable = JsonUtils.optBoolean(state, "isAvailable", true)
        if (state != null) {
            // disabled locations
            disabledLocations = state["disabledLocations"]
        }
    }

    fun isAvailable(): Boolean {
        return isAvailable
    }

    fun isLocationAvailable(cl: Location?): Boolean {
        if (cl == null) {
            return false
        }
        val dls = disabledLocations ?: return true
        val locStr = cl.id
        for (curr in dls) {
            if (locStr == curr.asText()) {
                return false
            }
        }
        return true
    }

    fun getLocationLimit(): Int {
        return getProp("locationFailoverLimit", 0)
    }

    fun getMaxDnsIps(): Int {
        return getProp("maxDnsIpsForLocation", 0)
    }

    @JsonIgnore
    fun getStaticDnsEntries(): JsonNode? {
        return staticDnsEntries
    }

    fun getDomain(): String? {
        return domain
    }

    fun getRoutingName(): String? {
        return routingName
    }

    fun getTopology(): String? {
        return topology
    }

    fun hasRequiredCapabilities(serverCapabilities: MutableSet<String?>?): Boolean {
        return serverCapabilities.containsAll(requiredCapabilities)
    }

    fun getDispersion(): Dispersion? {
        return dispersion
    }

    fun getGeoRedirectUrl(): String? {
        return geoRedirectUrl
    }

    fun getGeoRedirectUrlType(): String? {
        return geoRedirectUrlType
    }

    fun setGeoRedirectUrlType(type: String?) {
        geoRedirectUrlType = type
    }

    fun getGeoRedirectFile(): String? {
        return geoRedirectFile
    }

    fun setGeoRedirectFile(filePath: String?) {
        geoRedirectFile = filePath
    }

    fun isIp6RoutingEnabled(): Boolean {
        return ip6RoutingEnabled
    }

    fun getResponseHeaders(): MutableMap<String?, String?>? {
        return responseHeaders
    }

    @Throws(JsonUtilsException::class)
    private fun setResponseHeaders(jo: JsonNode?) {
        if (jo != null) {
            val keyIter = jo.fieldNames()
            while (keyIter.hasNext()) {
                val key = keyIter.next()
                responseHeaders[key] = JsonUtils.getString(jo, key)
            }
        }
    }

    fun getRequestHeaders(): MutableSet<String?>? {
        return requestHeaders
    }

    private fun setRequestHeaders(jsonRequestHeaderNames: JsonNode?) {
        if (jsonRequestHeaderNames == null) {
            return
        }
        for (name in jsonRequestHeaderNames) {
            requestHeaders.add(name.asText())
        }
    }

    fun isRegionalGeoEnabled(): Boolean {
        return regionalGeoEnabled
    }

    fun getGeolocationProvider(): String? {
        return geolocationProvider
    }

    fun isAnonymousIpEnabled(): Boolean {
        return anonymousIpEnabled
    }

    fun filterAvailableLocations(cacheLocations: MutableCollection<CacheLocation?>?): MutableList<CacheLocation?>? {
        val locations: MutableList<CacheLocation?> = ArrayList()
        for (cl in cacheLocations) {
            if (isLocationAvailable(cl)) {
                locations.add(cl)
            }
        }
        return locations
    }

    fun isSslEnabled(): Boolean {
        return sslEnabled
    }

    fun setHasX509Cert(hasX509Cert: Boolean) {
        this.hasX509Cert = hasX509Cert
    }

    fun isSslReady(): Boolean {
        return sslEnabled && hasX509Cert
    }

    fun isAcceptHttp(): Boolean {
        return acceptHttp
    }

    fun getConsistentHashRegex(): String? {
        return consistentHashRegex
    }

    fun setConsistentHashRegex(consistentHashRegex: String?) {
        this.consistentHashRegex = consistentHashRegex
    }

    /**
     * Extracts the significant parts of a request's query string based on this
     * Delivery Service's Consistent Hashing Query Parameters
     * @param r The request from which to extract query parameters
     * @return The parts of the request's query string relevant to consistent
     * hashing. The result is URI-decoded - if decoding fails it will return
     * a blank string instead.
     */
    fun extractSignificantQueryParams(r: HTTPRequest?): String? {
        if (r.getQueryString() == null || r.getQueryString().isEmpty() || getConsistentHashQueryParams().isEmpty()) {
            return ""
        }
        val qparams: SortedSet<String?> = TreeSet()
        try {
            for (qparam in r.getQueryString().split("&".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()) {
                if (qparam.isEmpty()) {
                    continue
                }
                val parts: Array<String?> = qparam.split("=".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                for (i in parts.indices) {
                    parts[i] = URLDecoder.decode(parts[i], "UTF-8")
                }
                if (getConsistentHashQueryParams().contains(parts[0])) {
                    qparams.add(java.lang.String.join("=", *parts))
                }
            }
        } catch (e: UnsupportedEncodingException) {
            val err = StringBuffer()
            err.append("Error decoding query parameters - ")
            err.append(this.toString())
            err.append(" - Exception: ")
            err.append(e.toString())
            LOGGER.error(err.toString())
            return ""
        }
        val s = StringBuilder()
        for (q in qparams) {
            s.append(q)
        }
        return s.toString()
    }

    fun isEcsEnabled(): Boolean {
        return ecsEnabled
    }

    fun setEcsEnabled(ecsEnabled: Boolean) {
        this.ecsEnabled = ecsEnabled
    }

    companion object {
        protected val LOGGER = LogManager.getLogger(DeliveryService::class.java)
        private const val STANDARD_HTTP_PORT = 80
        private const val STANDARD_HTTPS_PORT = 443
        private val REGEX_PERIOD: String? = "\\."
        var stringProtector: StringProtector? = null
        private fun getStringProtector(): StringProtector? {
            try {
                synchronized(LOGGER) {
                    if (stringProtector == null) {
                        stringProtector = StringProtector("HajUsyac7") // random passwd
                    }
                }
            } catch (e: GeneralSecurityException) {
                LOGGER.warn(e, e)
            }
            return stringProtector
        }

        var tid: AtomicInteger? = AtomicInteger(0)
        private fun getTid(): Int {
            return tid.incrementAndGet()
        }
    }
}