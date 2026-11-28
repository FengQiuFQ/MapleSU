package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.switch.HookResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** Exercises the real status client with distinct observation and transaction transports. */
class ModeSwitchStatusReadTest {
    @get:Rule val temp = TemporaryFolder()
    private val id = "11111111-1111-1111-1111-111111111111"
    private val complete = "MAPLESU_SWITCH_LIST_COMPLETE"
    private val absent = "MAPLESU_SWITCH_RECORD_ABSENT"

    @Test fun discoveringAnActualTaskDoesNotPrepareTheTransactionDaemon() = background {
        var preparations = 0
        val commands = mutableListOf<String>()
        val pin = ModeSwitchRootPin({ preparations++; HookResult.OK },
            { error("status read reached the transaction executor") }, { HookResult.OK })
        val client = client(pin::execute) { script ->
            commands += script
            reply(if (script.startsWith("#maplesu:list-tx\n")) "$id\n$complete\n" else state())
        }
        assertEquals(id, client.statusExact("")?.switchId)
        assertEquals("REBOOT_REQUIRED", client.statusExact(id)?.state)
        assertEquals(0, preparations)
        assertEquals(listOf("#maplesu:list-tx", "#maplesu:state-read", "#maplesu:state-read"),
            commands.map { it.lineSequence().first() })
    }

    @Test fun anEmptyHistoryIsReadAgainWithoutCreatingOrCachingATransaction() = background {
        var preparations = 0
        var reads = 0
        val pin = ModeSwitchRootPin({ preparations++; HookResult.OK },
            { error("empty history must not prepare a daemon") }, { HookResult.OK })
        val client = client(pin::execute) { script ->
            assertTrue(script.startsWith("#maplesu:list-tx\n"))
            reads++
            reply("$complete\n")
        }
        assertNull(client.statusExact(""))
        assertNull(client.statusExact(""))
        assertEquals(2, reads)
        assertEquals(0, preparations)
    }

    @Test fun anObservationFailureKeepsItsOriginalDetailWithoutStartingTheDaemon() = background {
        var preparations = 0
        var reads = 0
        val pin = ModeSwitchRootPin({ preparations++; HookResult.OK },
            { error("a failed read must not switch transport") }, { HookResult.OK })
        val client = client(pin::execute) {
            reads++
            RootExecResult(RootBackend.ULTRA_ENV, -1007, "", "MAPLESU_SDK_DEADLINE_EXCEEDED")
        }
        val error = runCatching { client.statusExact("") }.exceptionOrNull()
        assertEquals("MAPLESU_SDK_DEADLINE_EXCEEDED", error?.message)
        assertEquals(1, reads)
        assertEquals(0, preparations)
    }

    @Test fun anExactRecordReadFailureKeepsItsReceiptDetailAndDoesNotReadTheJournal() = background {
        var reads = 0
        val client = client({ error("exact failure must not prepare a transaction") }) { script ->
            assertTrue(script.startsWith("#maplesu:state-read\n"))
            reads++
            RootExecResult(RootBackend.ULTRA_ENV, -1007, "", "MAPLESU_SDK_DEADLINE_EXCEEDED")
        }
        val error = runCatching { client.statusExact(id) }.exceptionOrNull()
        assertEquals("MAPLESU_SDK_DEADLINE_EXCEEDED", error?.message)
        assertEquals(1, reads)
    }

    @Test fun missingExactTaskStillRequiresSuccessfulStateAndJournalReads() = background {
        val commands = mutableListOf<String>()
        val client = client({ error("exact absence must not start a transaction") }) { script ->
            commands += script
            reply(absent)
        }
        assertNull(client.statusExact(id))
        assertEquals(listOf("#maplesu:state-read", "#maplesu:journal-read"),
            commands.map { it.lineSequence().first() })
    }

    @Test fun theLegacyStatusEntryAlsoUsesItsObservationTransport() = background {
        val commands = mutableListOf<String>()
        val client = client({ error("legacy status must not start a transaction") }) { script ->
            commands += script
            reply(if (script.startsWith("#maplesu:list-tx\n")) id else state())
        }
        assertEquals(id, client.status("")?.switchId)
        assertEquals(listOf("#maplesu:list-tx", "#maplesu:state-read"),
            commands.map { it.lineSequence().first() })
    }

    @Test fun everyRemoteReadKeepsTheSameInheritedDeadline() = background {
        val deadlines = mutableListOf<Long?>()
        val parent = System.nanoTime() + 900_000_000L
        val client = client({ error("deadline-scoped status must not prepare a transaction") }) { script ->
            deadlines += PageReadDeadline.currentNanos()
            reply(if (script.startsWith("#maplesu:list-tx\n")) "$id\n$complete\n" else state())
        }
        val status = PageReadDeadline.onWorker(parent) { client.statusExact("") }
        assertEquals(id, status?.switchId)
        assertEquals(listOf(parent, parent), deadlines)
    }

    @Test fun transactionPreparationStillUsesItsOriginalExecutor() = runBlocking {
        var transactions = 0
        val client = client({
            transactions++
            RootExecResult(RootBackend.ULTRA_ENV, -1, "", "original-transaction-error")
        }) { error("transaction preparation must keep its original executor") }
        val result = client.preflight(id, mapOf("fromMode" to "LITE", "toMode" to "KSU", "targetPartition" to "init_boot"))
        assertFalse(result.ok)
        assertEquals("original-transaction-error", result.detail)
        assertEquals(1, transactions)
    }

    private fun client(transaction: (String) -> RootExecResult, observation: (String) -> RootExecResult) =
        UltraRootModeSwitchClient(runner = transaction, workRoot = File(temp.root, "remote"),
            statusRunner = observation)

    private fun state() = ControlJsonCodec.encode(UltraSwitchStateFile(
        switchId = id, state = "REBOOT_REQUIRED", fromMode = "KSU", toMode = "LITE", targetPartition = "boot"))

    private fun reply(output: String) = RootExecResult(RootBackend.ULTRA_ENV, 0, output)

    private inline fun <T> background(action: () -> T): T {
        val thread = Thread.currentThread()
        val previous = thread.name
        thread.name = "maplesu-status-read-test"
        return try { action() } finally { thread.name = previous }
    }
}
