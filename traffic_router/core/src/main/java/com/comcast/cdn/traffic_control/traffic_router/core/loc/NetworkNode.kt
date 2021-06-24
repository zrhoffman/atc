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
package com.comcast.cdn.traffic_control.traffic_router.core.loc

import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Location
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeException
import com.comcast.cdn.traffic_control.traffic_router.core.util.CidrAddress
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.TreeMap

open class NetworkNode @JvmOverloads constructor(
    str: String?,
    private val loc: String? = null,
    geolocation: Geolocation? = null
) : Comparable<NetworkNode?> {
    private val cidrAddress: CidrAddress?
    private var location: Location? = null
    private val geolocation: Geolocation? = null
    var children: MutableMap<NetworkNode?, NetworkNode?>? = null
    private var deepCacheNames: MutableSet<String?>? = null

    @Throws(NetworkNodeException::class)
    open fun getNetwork(ip: String?): NetworkNode? {
        return getNetwork(NetworkNode(ip))
    }

    fun getNetwork(ipnn: NetworkNode?): NetworkNode? {
        if (this.compareTo(ipnn) != 0) {
            return null
        }
        if (children == null) {
            return this
        }
        val c = children.get(ipnn) ?: return this
        return c.getNetwork(ipnn)
    }

    fun add(nn: NetworkNode?): Boolean? {
        synchronized(this) {
            if (children == null) {
                children = TreeMap()
            }
            return add(children, nn)
        }
    }

    protected fun add(children: MutableMap<NetworkNode?, NetworkNode?>?, networkNode: NetworkNode?): Boolean? {
        if (compareTo(networkNode) != 0) {
            return false
        }
        for (child in children.values) {
            if (child.cidrAddress == networkNode.cidrAddress) {
                return false
            }
        }
        val movedChildren: MutableList<NetworkNode?> = ArrayList()
        for (child in children.values) {
            if (networkNode.cidrAddress.includesAddress(child.cidrAddress)) {
                movedChildren.add(child)
                networkNode.add(child)
            }
        }
        for (movedChild in movedChildren) {
            children.remove(movedChild)
        }
        for (child in children.values) {
            if (child.cidrAddress.includesAddress(networkNode.cidrAddress)) {
                return child.add(networkNode)
            }
        }
        children[networkNode] = networkNode
        return true
    }

    fun getLoc(): String? {
        return loc
    }

    fun getGeolocation(): Geolocation? {
        return geolocation
    }

    fun getLocation(): Location? {
        return location
    }

    fun setLocation(location: Location?) {
        this.location = location
    }

    fun getDeepCacheNames(): MutableSet<String?>? {
        return deepCacheNames
    }

    fun setDeepCacheNames(deepCacheNames: MutableSet<String?>?) {
        this.deepCacheNames = deepCacheNames
    }

    fun size(): Int {
        if (children == null) {
            return 1
        }
        var size = 1
        for (child in children.keys) {
            size += child.size()
        }
        return size
    }

    @JvmOverloads
    fun clearLocations(clearCachesOnly: Boolean = false) {
        synchronized(this) {
            if (clearCachesOnly && location != null && location is CacheLocation) {
                (location as CacheLocation?).clearCaches()
            } else {
                location = null
            }
            if (this is SuperNode) {
                val superNode = this as SuperNode
                if (superNode.children6 != null) {
                    for (child in superNode.children6.keys) {
                        child.clearLocations(clearCachesOnly)
                    }
                }
            }
            if (children != null) {
                for (child in children.keys) {
                    child.clearLocations(clearCachesOnly)
                }
            }
        }
    }

    class SuperNode : NetworkNode(NetworkNode.Companion.DEFAULT_SUB_STR) {
        private var children6: MutableMap<NetworkNode?, NetworkNode?>? = null
        fun add6(nn: NetworkNode?): Boolean? {
            if (children6 == null) {
                children6 = TreeMap()
            }
            return add(children6, nn)
        }

        @Throws(NetworkNodeException::class)
        override fun getNetwork(ip: String?): NetworkNode? {
            val nn = NetworkNode(ip)
            return if (nn.cidrAddress.isIpV6) {
                getNetwork6(nn)
            } else getNetwork(nn)
        }

        fun getNetwork6(networkNode: NetworkNode?): NetworkNode? {
            if (children6 == null) {
                return this
            }
            val c = children6.get(networkNode) ?: return this
            return c.getNetwork(networkNode)
        }
    }

    override fun compareTo(other: NetworkNode?): Int {
        return cidrAddress.compareTo(other.cidrAddress)
    }

    override fun toString(): String {
        var str = ""
        try {
            str = InetAddress.getByAddress(cidrAddress.getHostBytes()).toString().replace("/", "")
        } catch (e: UnknownHostException) {
            NetworkNode.Companion.LOGGER.warn(e, e)
        }
        return "[" + str + "/" + cidrAddress.getNetmaskLength() + "] - location:" + getLoc()
    }

    companion object {
        private val LOGGER = Logger.getLogger(NetworkNode::class.java)
        private val DEFAULT_SUB_STR: String? = "0.0.0.0/0"
        private val instance: NetworkNode? = null
        private val deepInstance: NetworkNode? = null
        fun getInstance(): NetworkNode? {
            if (NetworkNode.Companion.instance != null) {
                return NetworkNode.Companion.instance
            }
            try {
                NetworkNode.Companion.instance = NetworkNode(NetworkNode.Companion.DEFAULT_SUB_STR)
            } catch (e: NetworkNodeException) {
                NetworkNode.Companion.LOGGER.warn(e)
            }
            return NetworkNode.Companion.instance
        }

        fun getDeepInstance(): NetworkNode? {
            if (NetworkNode.Companion.deepInstance != null) {
                return NetworkNode.Companion.deepInstance
            }
            try {
                NetworkNode.Companion.deepInstance = NetworkNode(NetworkNode.Companion.DEFAULT_SUB_STR)
            } catch (e: NetworkNodeException) {
                NetworkNode.Companion.LOGGER.warn(e)
            }
            return NetworkNode.Companion.deepInstance
        }

        @JvmOverloads
        @Throws(IOException::class)
        fun generateTree(f: File?, verifyOnly: Boolean, useDeep: Boolean = false): NetworkNode? {
            val mapper = ObjectMapper()
            return NetworkNode.Companion.generateTree(mapper.readTree(f), verifyOnly, useDeep)
        }

        @JvmOverloads
        fun generateTree(json: JsonNode?, verifyOnly: Boolean, useDeep: Boolean = false): NetworkNode? {
            try {
                val czKey = if (useDeep) "deepCoverageZones" else "coverageZones"
                val coverageZones = JsonUtils.getJsonNode(json, czKey)
                val root = SuperNode()
                val czIter = coverageZones.fieldNames()
                while (czIter.hasNext()) {
                    val loc = czIter.next()
                    val locData = JsonUtils.getJsonNode(coverageZones, loc)
                    val coordinates = locData["coordinates"]
                    var geolocation: Geolocation? = null
                    if (coordinates != null && coordinates.has("latitude") && coordinates.has("longitude")) {
                        val latitude = coordinates["latitude"].asDouble()
                        val longitude = coordinates["longitude"].asDouble()
                        geolocation = Geolocation(latitude, longitude)
                    }
                    if (!NetworkNode.Companion.addNetworkNodesToRoot(root, loc, locData, geolocation, useDeep)) {
                        return null
                    }
                }
                if (!verifyOnly) {
                    if (useDeep) {
                        NetworkNode.Companion.deepInstance = root
                    } else {
                        NetworkNode.Companion.instance = root
                    }
                }
                return root
            } catch (ex: JsonUtilsException) {
                NetworkNode.Companion.LOGGER.warn(ex, ex)
            } catch (ex: NetworkNodeException) {
                NetworkNode.Companion.LOGGER.fatal(ex, ex)
            }
            return null
        }

        private fun addNetworkNodesToRoot(
            root: SuperNode?, loc: String?, locData: JsonNode?,
            geolocation: Geolocation?, useDeep: Boolean
        ): Boolean {
            val deepLoc = CacheLocation("deep.$loc", geolocation ?: Geolocation(0.0, 0.0)) // TODO JvD
            val cacheNames: MutableSet<String?> = NetworkNode.Companion.parseDeepCacheNames(locData)
            for (key in arrayOf<String?>("network6", "network")) {
                try {
                    for (network in JsonUtils.getJsonNode(locData, key)) {
                        val ip = network.asText()
                        try {
                            val nn = NetworkNode(ip, loc, geolocation)
                            if (useDeep) {
                                // For a deep NetworkNode, we set the CacheLocation here without any Caches.
                                // The deep Caches will be lazily loaded in getCoverageZoneCacheLocation() where we have
                                // access to the latest CacheRegister, similar to how normal NetworkNodes are lazily loaded
                                // with a CacheLocation.
                                nn.deepCacheNames = cacheNames
                                nn.location = deepLoc
                            }
                            if ("network6" == key) {
                                root.add6(nn)
                            } else {
                                root.add(nn)
                            }
                        } catch (ex: NetworkNodeException) {
                            NetworkNode.Companion.LOGGER.error(ex, ex)
                            return false
                        }
                    }
                } catch (ex: JsonUtilsException) {
                    NetworkNode.Companion.LOGGER.warn("An exception was caught while accessing the " + key + " key of " + loc + " in the incoming coverage zone file: " + ex.message)
                }
            }
            return true
        }

        private fun parseDeepCacheNames(locationData: JsonNode?): MutableSet<String?>? {
            val cacheNames: MutableSet<String?> = HashSet()
            val cacheArray: JsonNode?
            cacheArray = try {
                JsonUtils.getJsonNode(locationData, "caches")
            } catch (ex: JsonUtilsException) {
                return cacheNames
            }
            for (cache in cacheArray) {
                val cacheName = cache.asText()
                if (!cacheName.isEmpty()) {
                    cacheNames.add(cacheName)
                }
            }
            return cacheNames
        }
    }

    init {
        this.geolocation = geolocation
        cidrAddress = CidrAddress.Companion.fromString(str)
    }
}