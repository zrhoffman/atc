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

import com.fasterxml.jackson.annotation.JsonProperty

class RegionalGeoCoordinateRange {
    @JsonProperty
    private var minLat = 0.0

    @JsonProperty
    private var minLon = 0.0

    @JsonProperty
    private var maxLat = 0.0

    @JsonProperty
    private var maxLon = 0.0
    fun getMinLat(): Double {
        return minLat
    }

    fun setMinLat(minLat: Double) {
        this.minLat = minLat
    }

    fun getMinLon(): Double {
        return minLon
    }

    fun setMinLon(minLon: Double) {
        this.minLon = minLon
    }

    fun getMaxLat(): Double {
        return maxLat
    }

    fun setMaxLat(maxLat: Double) {
        this.maxLat = maxLat
    }

    fun getMaxLon(): Double {
        return maxLon
    }

    fun setMaxLon(maxLon: Double) {
        this.maxLon = maxLon
    }
}