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
package com.comcast.cdn.traffic_control.traffic_router.core.hash

import java.util.Arrays

object NumberSearcher {
    fun findClosest(numbers: Array<Double?>?, target: Double): Int {
        val index = Arrays.binarySearch(numbers, target)
        if (index >= 0) {
            return index
        }
        val biggerThanIndex = -(index + 1)
        if (biggerThanIndex == numbers.size) {
            return numbers.size - 1
        }
        if (biggerThanIndex == 0) {
            return 0
        }
        val smallerThanIndex = biggerThanIndex - 1
        val biggerThanDelta = Math.abs(numbers.get(biggerThanIndex) - target)
        val smallerThanDelta = Math.abs(numbers.get(smallerThanIndex) - target)
        return if (biggerThanDelta < smallerThanDelta) biggerThanIndex else smallerThanIndex
    }
}