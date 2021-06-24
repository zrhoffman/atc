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
package com.comcast.cdn.traffic_control.traffic_router.core.util

abstract class AbstractUpdatable {
    private var lastUpdated: Long = 0
    abstract fun update(newDB: String?): Boolean
    abstract fun noChange(): Boolean
    open fun complete() {
        // override if you wish to exec code after the download is complete
    }

    fun getLastUpdated(): Long {
        return lastUpdated
    }

    fun setLastUpdated(lastUpdated: Long) {
        this.lastUpdated = lastUpdated
    }

    open fun cancelUpdate() {}
}