/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.comcast.cdn.traffic_control.traffic_router.core.edge

/**
 * An abbreviated version of CacheLocation to show only properties and a list of cache names
 */
class PropertiesAndCaches(cacheLocation: CacheLocation?) {
    val properties: MutableMap<String?, String?>?
    val caches: MutableList<String?>?

    /**
     * Gets properties.
     *
     * @return the properties
     */
    fun getProperties(): MutableMap<String?, String?>? {
        return properties
    }

    /**
     * Gets caches.
     *
     * @return the caches
     */
    fun getCaches(): MutableList<String?>? {
        return caches
    }

    init {
        properties = cacheLocation.getProperties()
        caches = ArrayList()
        for (cache in cacheLocation.getCaches()) {
            caches.add(cache.id)
        }
    }
}