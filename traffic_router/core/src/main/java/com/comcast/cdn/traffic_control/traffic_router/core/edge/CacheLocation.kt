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
package com.comcast.cdn.traffic_control.traffic_router.core.edge

import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.apache.log4j.Logger
import java.util.Arrays

/**
 * A physical location that has caches.
 */
class CacheLocation @JvmOverloads constructor(
    id: String?,
    geolocation: Geolocation?,
    backupCacheGroups: MutableList<String?>? = null,
    useClosestGeoOnBackupFailure: Boolean = true,
    enabledLocalizationMethods: MutableSet<LocalizationMethod?>? = HashSet()
) : Location(id, geolocation) {
    private val caches: MutableMap<String?, Cache?>?
    private val backupCacheGroups: MutableList<String?>? = null
    private val useClosestGeoOnBackupFailure = true
    private val enabledLocalizationMethods: MutableSet<LocalizationMethod?>?

    enum class LocalizationMethod {
        DEEP_CZ, CZ, GEO
    }

    constructor(
        id: String?,
        geoLocation: Geolocation?,
        enabledLocalizationMethods: MutableSet<LocalizationMethod?>?
    ) : this(id, geoLocation, null, true, enabledLocalizationMethods) {
    }

    fun isEnabledFor(localizationMethod: LocalizationMethod?): Boolean {
        return enabledLocalizationMethods.contains(localizationMethod)
    }

    /**
     * Adds the specified cache to this location.
     *
     * @param cache
     * the cache to add
     */
    fun addCache(cache: Cache?) {
        synchronized(caches) { caches.put(cache.getId(), cache) }
    }

    fun clearCaches() {
        synchronized(caches) { caches.clear() }
    }

    fun loadDeepCaches(deepCacheNames: MutableSet<String?>?, cacheRegister: CacheRegister?) {
        synchronized(caches) {
            if (caches.isEmpty() && deepCacheNames != null) {
                for (deepCacheName in deepCacheNames) {
                    val deepCache = cacheRegister.getCacheMap()[deepCacheName]
                    if (deepCache != null) {
                        CacheLocation.Companion.LOGGER.debug("DDC: Adding $deepCacheName to $id")
                        caches[deepCache.id] = deepCache
                    }
                }
            }
        }
    }

    override fun equals(obj: Any?): Boolean {
        return if (this === obj) {
            true
        } else if (obj is CacheLocation) {
            val rhs = obj as CacheLocation?
            EqualsBuilder()
                .append(id, rhs.getId())
                .isEquals
        } else {
            false
        }
    }

    /**
     * Retrieves the specified [Cache] from the location.
     *
     * @param id
     * the ID for the desired `Cache`
     * @return the cache or `null` if the cache doesn't exist
     */
    fun getCache(id: String?): Cache? {
        return caches.get(id)
    }

    /**
     * Retrieves the [Set] of caches at this location.
     *
     * @return the caches
     */
    fun getCaches(): MutableList<Cache?>? {
        return ArrayList(caches.values)
    }

    /**
     * Gets backupCacheGroups.
     *
     * @return the backupCacheGroups
     */
    fun getBackupCacheGroups(): MutableList<String?>? {
        return backupCacheGroups
    }

    /**
     * Tests useClosestGeoOnBackupFailure.
     *
     * @return useClosestGeoOnBackupFailure
     */
    fun isUseClosestGeoLoc(): Boolean {
        return useClosestGeoOnBackupFailure
    }

    /**
     * Determines if the specified [Cache] exists at this location.
     *
     * @param id
     * the `Cache` to check
     * @return true if the `Cache` is at this location, false otherwise
     */
    fun hasCache(id: String?): Boolean {
        return caches.containsKey(id)
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
            .append(id)
            .toHashCode()
    }

    companion object {
        val LOGGER = Logger.getLogger(CacheLocation::class.java)
    }
    /**
     * Creates a CacheLocation with the specified ID at the specified location.
     *
     * @param id
     * the id of the location
     * @param geolocation
     * the coordinates of this location
     *
     * @param backupCacheGroups
     * the backup cache groups for this id
     *
     * @param useClosestGeoOnBackupFailure
     * the backup fallback setting for this id
     */
    /**
     * Creates a CacheLocation with the specified ID at the specified location.
     *
     * @param id
     * the id of the location
     * @param geolocation
     * the coordinates of this location
     */
    init {
        this.backupCacheGroups = backupCacheGroups
        this.useClosestGeoOnBackupFailure = useClosestGeoOnBackupFailure
        this.enabledLocalizationMethods = enabledLocalizationMethods
        if (this.enabledLocalizationMethods.isEmpty()) {
            this.enabledLocalizationMethods.addAll(Arrays.asList(*CacheLocation.LocalizationMethod.values()))
        }
        caches = HashMap()
    }
}