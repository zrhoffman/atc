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

import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessRecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServer
import org.apache.log4j.Logger
import org.xbill.DNS.Message
import org.xbill.DNS.Rcode
import org.xbill.DNS.Section
import org.xbill.DNS.WireParseException
import java.net.InetAddress
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

abstract class AbstractProtocol : Protocol {
    protected var shutdownRequested = false
    private var executorService: ThreadPoolExecutor? = null
    private var cancelService: ExecutorService? = null
    private var nameServer: NameServer? = null
    private var taskTimeout = 5000 // default
    private var queueDepth = 1000 // default

    /**
     * Gets executorService.
     *
     * @return the executorService
     */
    fun getExecutorService(): ThreadPoolExecutor? {
        return executorService
    }

    /**
     * Gets nameServer.
     *
     * @return the nameServer
     */
    fun getNameServer(): NameServer? {
        return nameServer
    }

    /**
     * Sets executorService.
     *
     * @param executorService
     * the executorService to set
     */
    fun setExecutorService(executorService: ThreadPoolExecutor?) {
        this.executorService = executorService
    }

    /**
     * Sets nameServer.
     *
     * @param nameServer
     * the nameServer to set
     */
    fun setNameServer(nameServer: NameServer?) {
        this.nameServer = nameServer
    }

    override fun shutdown() {
        shutdownRequested = true
        executorService.shutdownNow()
        cancelService.shutdownNow()
    }

    /**
     * Returns the maximum length of the response.
     *
     * @param request
     *
     * @return the maximum length in bytes
     */
    protected abstract fun getMaxResponseLength(request: Message?): Int

    /**
     * Gets shutdownRequested.
     *
     * @return the shutdownRequested
     */
    protected fun isShutdownRequested(): Boolean {
        return shutdownRequested
    }

    /**
     * Queries the DNS nameServer and returns the response.
     *
     * @param client
     * the IP address of the client
     * @param request
     * the DNS request in wire format
     * @return the DNS response in wire format
     */
    @Throws(WireParseException::class)
    protected fun query(client: InetAddress?, request: ByteArray?): ByteArray? {
        var query: Message? = null
        var response: Message? = null
        val queryTimeMillis = System.currentTimeMillis()
        val builder = DNSAccessRecord.Builder(queryTimeMillis, client)
        var dnsAccessRecord = builder.build()
        try {
            query = Message(request)
            dnsAccessRecord = builder.dnsMessage(query).build()
            response = getNameServer().query(query, client, builder)
            dnsAccessRecord = builder.dnsMessage(response).build()
            ACCESS.info(DNSAccessEventBuilder.create(dnsAccessRecord))
        } catch (e: WireParseException) {
            ACCESS.info(DNSAccessEventBuilder.create(dnsAccessRecord, e))
            throw e
        } catch (e: Exception) {
            ACCESS.info(DNSAccessEventBuilder.create(dnsAccessRecord, e))
            response = createServerFail(query)
        }
        return response.toWire(getMaxResponseLength(query))
    }

    /**
     * Submits a request handler to be executed.
     *
     * @param job
     * the handler to be executed
     */
    fun submit(job: SocketHandler?) {
        val queueLength = executorService.getQueue().size
        val handler: Future<*>?
        handler = if (queueDepth > 0 && queueLength >= queueDepth || queueDepth == 0 && queueLength > 0) {
            LOGGER.warn(
                String.format(
                    "%s request thread pool full and queue depth limit reached (%d >= %d); discarding request",
                    this.javaClass.simpleName, queueLength, queueDepth
                )
            )

            // causes the underlying SocketHandler inner class of each implementing protocol to call a cleanup() method
            job.cancel()

            // add to the cancellation thread pool instead of the task executor pool
            cancelService.submit(job)
        } else {
            executorService.submit(job)
        }
        cancelService.submit(getCanceler(handler))
    }

    private fun getCanceler(handler: Future<*>?): Runnable? {
        return Runnable {
            try {
                handler.get(getTaskTimeout().toLong(), TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                handler.cancel(true)
            } catch (e: ExecutionException) {
                handler.cancel(true)
            } catch (e: TimeoutException) {
                handler.cancel(true)
            }
        }
    }

    private fun createServerFail(query: Message?): Message? {
        val response = Message()
        if (query != null) {
            response.header = query.header
            // This has the side effect of clearing counts out of the header
            for (i in 0 until NUM_SECTIONS) {
                response.removeAllRecords(i)
            }
            response.addRecord(query.question, Section.QUESTION)
        }
        response.header.rcode = Rcode.SERVFAIL
        return response
    }

    fun getTaskTimeout(): Int {
        return taskTimeout
    }

    fun setTaskTimeout(taskTimeout: Int) {
        this.taskTimeout = taskTimeout
    }

    fun setQueueDepth(queueDepth: Int) {
        this.queueDepth = queueDepth
    }

    fun getCancelService(): ExecutorService? {
        return cancelService
    }

    fun setCancelService(cancelService: ExecutorService?) {
        this.cancelService = cancelService
    }

    companion object {
        private val ACCESS = Logger.getLogger("com.comcast.cdn.traffic_control.traffic_router.core.access")
        private val LOGGER = Logger.getLogger(AbstractProtocol::class.java)
        private const val NUM_SECTIONS = 4
    }
}