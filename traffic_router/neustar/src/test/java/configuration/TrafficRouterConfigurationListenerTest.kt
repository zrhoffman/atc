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
package configuration

import com.comcast.cdn.traffic_control.traffic_router.neustar.configuration.ServiceRefresher

class TrafficRouterConfigurationListenerTest {
    @Mock
    var scheduledExecutorService: ScheduledExecutorService? = null

    @Mock
    var environment: Environment? = null

    @Mock
    var serviceRefresher: ServiceRefresher? = null

    @InjectMocks
    var trafficRouterConfigurationListener: TrafficRouterConfigurationListener? = null

    @Before
    fun before() {
        initMocks(this)
        `when`(environment.getProperty("neustar.polling.interval", Long::class.java, 86400000L)).thenReturn(86400000L)
    }

    @Test
    fun itCancelsExistingTaskBeforeStartingAnother() {
        val scheduledFuture: ScheduledFuture = mock(ScheduledFuture::class.java)
        `when`(scheduledFuture.isDone()).thenAnswer(object : Answer<Boolean?>() {
            var doneCheckCount = 0

            @Override
            @Throws(Throwable::class)
            fun answer(invocation: InvocationOnMock?): Boolean? {
                doneCheckCount++
                return doneCheckCount > 3
            }
        })
        doReturn(scheduledFuture).`when`(scheduledExecutorService)
            .scheduleAtFixedRate(any(Runnable::class.java), eq(0L), eq(86400000L), eq(TimeUnit.MILLISECONDS))
        trafficRouterConfigurationListener.configurationChanged()
        verifyZeroInteractions(scheduledFuture)
        trafficRouterConfigurationListener.configurationChanged()
        verify(scheduledFuture).cancel(true)
        verify(scheduledFuture, times(4)).isDone()
    }
}