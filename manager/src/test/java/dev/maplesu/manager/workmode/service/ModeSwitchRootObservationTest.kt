package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.runtime.RootExecutionRouter
import dev.maplesu.manager.runtime.RootExecutor
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.HookResult
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class ModeSwitchRootObservationTest {
    @After fun cleanup() { RootExec.resetForTest() }

    @Test fun anOrdinaryObservationUsesTheExistingRouterWithoutPreparingADaemon() {
        var prepared = 0
        var reads = 0
        val root = object : RootExecutor {
            override val backend = RootBackend.ULTRA_ENV
            override fun available() = true
            override fun run(script: String): RootExecResult {
                reads++
                assertEquals("read-current-record", script)
                return reply("current-record")
            }
        }
        RootExec.installForTest(RootExecutionRouter(root, modeProvider = { WorkMode.LITE }))
        val pin = ModeSwitchRootPin({ prepared++; HookResult.OK },
            { error("observation must not open the transaction executor") }, { HookResult.OK })
        assertEquals("current-record", pin.observe("read-current-record", RootExec::execute).output)
        assertEquals(1, reads)
        assertEquals(0, prepared)
    }

    @Test fun anObservationOnAPreparedTransactionKeepsTheOriginalExecutor() {
        var prepared = 0
        val commands = mutableListOf<String>()
        val pin = ModeSwitchRootPin({ prepared++; HookResult.OK },
            { commands += it; reply("pinned-record") }, { HookResult.OK })
        assertTrue(pin.ensureReady().ok)
        assertEquals("pinned-record", pin.observe("read-after-teardown") {
            error("prepared transaction must not select an ordinary source")
        }.output)
        assertEquals(listOf("read-after-teardown"), commands)
        assertEquals(1, prepared)
    }

    @Test fun aLostMutationReplyKeepsObservationsQuarantinedWithoutAnotherSource() {
        var prepared = 0
        var submissions = 0
        val pin = ModeSwitchRootPin({ prepared++; HookResult.OK }, {
            submissions++
            RootExecResult(RootBackend.ULTRA_ENV, -1, "", ModeSwitchRootProtocol.UNCERTAIN)
        }, { HookResult.OK })
        assertEquals(ModeSwitchRootProtocol.UNCERTAIN, pin.execute("write-once").detail)
        assertEquals(ModeSwitchRootProtocol.UNCERTAIN, pin.observe("observe") {
            error("an uncertain mutation must keep its original quarantine")
        }.detail)
        assertEquals(1, prepared)
        assertEquals(1, submissions)
    }

    @Test fun anObservationFailureBeforeReadinessDoesNotPoisonAnExplicitTransaction() {
        var prepared = 0
        var submissions = 0
        val failedRead = RootExecResult(RootBackend.ULTRA_ENV, -1007, "", "MAPLESU_SDK_DEADLINE_EXCEEDED")
        val pin = ModeSwitchRootPin({ prepared++; HookResult.OK },
            { submissions++; reply("submitted-once") }, { HookResult.OK })
        assertSame(failedRead, pin.observe("read") { failedRead })
        assertEquals(0, prepared)
        assertTrue(pin.execute("explicit-operation").ok)
        assertEquals(1, prepared)
        assertEquals(1, submissions)
    }

    @Test fun anExpiredParentDeadlineReachesTheOrdinaryRouterWithoutPreparingOrExecuting() {
        var prepared = 0
        var submitted = 0
        val root = object : RootExecutor {
            override val backend = RootBackend.ULTRA_ENV
            override fun available() = true
            override fun run(script: String): RootExecResult { submitted++; return reply("") }
        }
        RootExec.installForTest(RootExecutionRouter(root, modeProvider = { WorkMode.LITE }))
        val pin = ModeSwitchRootPin({ prepared++; HookResult.OK },
            { error("expired observation must not prepare") }, { HookResult.OK })
        val result = PageReadDeadline.onWorker(System.nanoTime() - 1L) {
            pin.observe("read-expired", RootExec::execute)
        }
        assertEquals(-1007, result.code)
        assertEquals("ROOT_EXECUTION_DEADLINE_EXCEEDED", result.detail)
        assertEquals(0, prepared)
        assertEquals(0, submitted)
    }

    private fun reply(output: String) = RootExecResult(RootBackend.ULTRA_ENV, 0, output)
}
