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
package com.comcast.cdn.traffic_control.traffic_router.core.ds

import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation

class SteeringGeolocationComparator(private val clientLocation: Geolocation?) : Comparator<SteeringResult?> {
    override fun compare(result1: SteeringResult?, result2: SteeringResult?): Int {
        val originGeo1 = result1.getSteeringTarget().geolocation
        val originGeo2 = result2.getSteeringTarget().geolocation
        val cacheGeo1 = result1.getCache().geolocation
        val cacheGeo2 = result2.getCache().geolocation

        // null origin geolocations are considered greater than (i.e. farther away) than non-null origin geolocations
        if (originGeo1 != null && originGeo2 == null) {
            return -1
        }
        if (originGeo1 == null && originGeo2 != null) {
            return 1
        }
        if (originGeo1 == null && originGeo2 == null) {
            return 0
        }

        // same cache and origin locations, prefer lower geoOrder
        if (cacheGeo1 == cacheGeo2 && originGeo1 == originGeo2) {
            return Integer.compare(result1.getSteeringTarget().geoOrder, result2.getSteeringTarget().geoOrder)
        }
        val distanceFromClientToCache1 = clientLocation.getDistanceFrom(cacheGeo1)
        val distanceFromClientToCache2 = clientLocation.getDistanceFrom(cacheGeo2)
        val distanceFromCacheToOrigin1 = cacheGeo1.getDistanceFrom(originGeo1)
        val distanceFromCacheToOrigin2 = cacheGeo2.getDistanceFrom(originGeo2)
        val totalDistance1 = distanceFromClientToCache1 + distanceFromCacheToOrigin1
        val totalDistance2 = distanceFromClientToCache2 + distanceFromCacheToOrigin2

        // different cache and origin locations, prefer shortest total distance
        return if (totalDistance1 != totalDistance2) {
            // TODO: if the difference is smaller than a certain threshold/ratio, still prefer the closer edge even though distance is greater?
            java.lang.Double.compare(totalDistance1, totalDistance2)
        } else java.lang.Double.compare(distanceFromClientToCache1, distanceFromClientToCache2)

        // total distance is equal, prefer the closest edge to the client
    }
}