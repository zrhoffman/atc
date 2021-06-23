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
package com.comcast.cdn.traffic_control.traffic_router.neustar.files

import org.apache.log4j.Logger

class FilesMover {
    fun purgeDirectory(directory: File?): Boolean {
        return try {
            Files.walkFileTree(Paths.get(directory.getAbsolutePath()), object : SimpleFileVisitor<Path?>() {
                @Override
                @Throws(IOException::class)
                fun visitFile(file: Path?, basicFileAttributes: BasicFileAttributes?): FileVisitResult? {
                    Files.delete(file)
                    return FileVisitResult.CONTINUE
                }
            })
            true
        } catch (e: IOException) {
            LOGGER.error("Failed purging directory " + directory.getAbsolutePath().toString() + ": " + e.getMessage())
            false
        }
    }

    fun moveFiles(sourceDirectory: File?, destinationDirectory: File?): Boolean {
        if (!destinationDirectory.exists() && !destinationDirectory.mkdirs()) {
            return false
        }
        if (!destinationDirectory.canWrite()) {
            return false
        }
        for (file in sourceDirectory.listFiles()) {
            if (file.isDirectory()) {
                continue
            }
            val source: Path = Paths.get(file.getAbsolutePath())
            val destination: Path = Paths.get(destinationDirectory.getAbsolutePath(), file.getName())
            try {
                Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: IOException) {
                return false
            }
        }
        return true
    }

    fun updateCurrent(currentDirectory: File?, newDirectory: File?, oldDirectory: File?): Boolean {
        if (!currentDirectory.canWrite() || !newDirectory.canWrite()) {
            return false
        }
        if (oldDirectory.exists() && !purgeDirectory(oldDirectory)) {
            return false
        }
        if (!moveFiles(currentDirectory, oldDirectory)) {
            return false
        }
        if (!moveFiles(newDirectory, currentDirectory)) {
            moveFiles(oldDirectory, currentDirectory)
            return false
        }
        purgeDirectory(oldDirectory)
        return true
    }

    companion object {
        private val LOGGER: Logger? = Logger.getLogger(FilesMover::class.java)
    }
}