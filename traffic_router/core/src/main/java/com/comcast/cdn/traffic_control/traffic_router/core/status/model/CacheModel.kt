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
package com.comcast.cdn.traffic_control.traffic_router.core.status.model

/**
 * Model for a Cache.
 */
class CacheModel {
    private var cacheId: String? = null
    private var fqdn: String? = null
    private var ipAddresses: MutableList<String?>? = null
    private var port = 0
    private var adminStatus: String? = null
    private var lastUpdateHealthy = false
    private var lastUpdateTime: Long = 0
    private var connections: Long = 0
    private var currentBW: Long = 0
    private var availBW: Long = 0
    var cacheOnline = false

    /**
     * Gets adminStatus.
     *
     * @return the adminStatus
     */
    fun getAdminStatus(): String? {
        return adminStatus
    }

    /**
     * Gets cacheId.
     *
     * @return the cacheId
     */
    fun getCacheId(): String? {
        return cacheId
    }

    /**
     * Gets fqdn.
     *
     * @return the fqdn
     */
    fun getFqdn(): String? {
        return fqdn
    }

    /**
     * Gets ipAddresses.
     *
     * @return the ipAddresses
     */
    fun getIpAddresses(): MutableList<String?>? {
        return ipAddresses
    }

    /**
     * Gets lastUpdateTime.
     *
     * @return the lastUpdateTime
     */
    fun getLastUpdateTime(): Long {
        return lastUpdateTime
    }

    /**
     * Gets port.
     *
     * @return the port
     */
    fun getPort(): Int {
        return port
    }

    /**
     * Gets lastUpdateHealth.
     *
     * @return the lastUpdateHealth
     */
    fun isLastUpdateHealthy(): Boolean {
        return lastUpdateHealthy
    }

    /**
     * Sets adminStatus.
     *
     * @param adminStatus
     * the adminStatus to set
     */
    fun setAdminStatus(adminStatus: String?) {
        this.adminStatus = adminStatus
    }

    /**
     * Sets cacheId.
     *
     * @param cacheId
     * the cacheId to set
     */
    fun setCacheId(cacheId: String?) {
        this.cacheId = cacheId
    }

    /**
     * Sets fqdn.
     *
     * @param fqdn
     * the fqdn to set
     */
    fun setFqdn(fqdn: String?) {
        this.fqdn = fqdn
    }

    /**
     * Sets lastUpdateHealthy.
     *
     * @param lastUpdateHealthy
     * the lastUpdateHealthy to set
     */
    fun setLastUpdateHealthy(lastUpdateHealthy: Boolean) {
        this.lastUpdateHealthy = lastUpdateHealthy
    }

    /**
     * Sets ipAddresses.
     *
     * @param ipAddresses
     * the ipAddresses to set
     */
    fun setIpAddresses(ipAddresses: MutableList<String?>?) {
        this.ipAddresses = ipAddresses
    }

    /**
     * Sets lastUpdateTime.
     *
     * @param lastUpdateTime
     * the lastUpdateTime to set
     */
    fun setLastUpdateTime(lastUpdateTime: Long) {
        this.lastUpdateTime = lastUpdateTime
    }

    /**
     * Sets port.
     *
     * @param port
     * the port to set
     */
    fun setPort(port: Int) {
        this.port = port
    }

    fun setConnections(numConn: Long) {
        connections = numConn
    }

    fun getConnections(): Long {
        return connections
    }

    fun getCurrentBW(): Long {
        return currentBW
    }

    fun getAvailBW(): Long {
        return availBW
    }

    fun setCurrentBW(currBW: Long) {
        currentBW = currBW
    }

    fun setAvailBW(availBW: Long) {
        this.availBW = availBW
    }

    fun isCacheOnline(): Boolean {
        return cacheOnline
    }
}