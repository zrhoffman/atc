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
package com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol

import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP
import org.apache.log4j.Logger
import org.xbill.DNS.Message
import org.xbill.DNS.WireParseException
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.nio.channels.Channels

class TCP : AbstractProtocol() {
    private var readTimeout = 3000 // default
    private var serverSocket: ServerSocket? = null

    /**
     * Gets serverSocket.
     *
     * @return the serverSocket
     */
    fun getServerSocket(): ServerSocket? {
        return serverSocket
    }

    override fun run() {
        while (!isShutdownRequested) {
            try {
                val socket = getServerSocket().accept()
                val handler = TCPSocketHandler(socket)
                submit(handler)
            } catch (e: IOException) {
                TCP.Companion.LOGGER.warn("error: $e")
            }
        }
    }

    /**
     * Sets serverSocket.
     *
     * @param serverSocket
     * the serverSocket to set
     */
    fun setServerSocket(serverSocket: ServerSocket?) {
        this.serverSocket = serverSocket
    }

    public override fun getMaxResponseLength(request: Message?): Int {
        return Int.MAX_VALUE
    }

    /**
     * This class is package private for unit testing purposes.
     */
    internal inner class TCPSocketHandler
    /**
     * This method is package private for unit testing purposes.
     *
     * @param socket
     */(private val socket: Socket?) : SocketHandler {
        private var cancel = false
        override fun run() {
            if (cancel) {
                cleanup()
                return
            }
            try {
                socket.setSoTimeout(getReadTimeout())
                val client = socket.getInetAddress()
                val iis = Channels.newInputStream(
                    Channels.newChannel(
                        socket.getInputStream()
                    )
                )
                val `is` = DataInputStream(iis)
                val os = DataOutputStream(socket.getOutputStream())
                val length = `is`.readUnsignedShort()
                val request = ByteArray(length)
                `is`.readFully(request)
                val response = query(client, request)
                os.writeShort(response.size)
                os.write(response)
            } catch (e: WireParseException) {
                // This is already recorded in the access log
            } catch (e: Exception) {
                TCP.Companion.LOGGER.error(e.message, e)
            } finally {
                cleanup()
            }
        }

        override fun cleanup() {
            if (socket == null) {
                return
            }
            try {
                socket.close()
            } catch (e: IOException) {
                TCP.Companion.LOGGER.debug(e.message, e)
            }
        }

        override fun cancel() {
            cancel = true
        }
    }

    override fun shutdown() {
        super.shutdown()
        try {
            serverSocket.close()
        } catch (e: IOException) {
            TCP.Companion.LOGGER.warn("error on shutdown", e)
        }
    }

    fun getReadTimeout(): Int {
        return readTimeout
    }

    fun setReadTimeout(readTimeout: Int) {
        this.readTimeout = readTimeout
    }

    companion object {
        private val LOGGER = Logger.getLogger(TCP::class.java)
    }
}