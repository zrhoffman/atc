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

import java.io.File
import java.io.IOException

open class NetworkUpdater : AbstractServiceUpdater() {
    @Throws(IOException::class)
    override fun loadDatabase(): Boolean {
        val existingDB = databasesDirectory.resolve(databaseName).toFile()
        return if (!existingDB.exists() || !existingDB.canRead()) {
            false
        } else generateTree(existingDB, false) != null
    }

    @Throws(IOException::class)
    override fun verifyDatabase(dbFile: File?): Boolean {
        return if (!dbFile.exists() || !dbFile.canRead()) {
            false
        } else generateTree(dbFile, true) != null
    }

    @Throws(IOException::class)
    open fun generateTree(dbFile: File?, verifyOnly: Boolean): NetworkNode? {
        return generateTree(dbFile, verifyOnly)
    }

    init {
        sourceCompressed = false
        tmpPrefix = "czf"
        tmpSuffix = ".json"
    }
}