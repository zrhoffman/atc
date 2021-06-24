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
package com.comcast.cdn.traffic_control.traffic_router.core.router

import com.comcast.cdn.traffic_control.traffic_router.core.edge.Location
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation

/**
 *
 */
class LocationComparator
/**
 * @param sourceLocation
 */(private val sourceLocation: Geolocation?) : Comparator<Location?> {
    /*
     * (non-Javadoc)
     * 
     * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
     */
    override fun compare(loc1: Location?, loc2: Location?): Int {
        val d1 = sourceLocation.getDistanceFrom(loc1.getGeolocation())
        val d2 = sourceLocation.getDistanceFrom(loc2.getGeolocation())
        return d1.compareTo(d2)
    }
}