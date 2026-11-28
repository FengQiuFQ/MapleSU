// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.PageReadDeadline
import java.io.File
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UltraSuProcessExecTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun anExpiredSharedDeadlineDoesNotStartAProbe() {
        val calls = AtomicInteger()
        val channel = UltraSuChannel(exec = { _, _, _ -> calls.incrementAndGet(); SuExecResult(0, "0\n") })
        val uid = PageReadDeadline.onWorker(System.nanoTime() - 1L) { channel.rootUid() }
        assertNull(uid)
        assertEquals(0, calls.get())
        assertEquals("SU_TIMEOUT", channel.lastFailure)
    }

    @Test fun anExpiredSharedDeadlineDoesNotSubmitACommandThroughADiscoveredPath() {
        val calls = AtomicInteger()
        val channel = UltraSuChannel(exec = { _, _, _ -> calls.incrementAndGet(); SuExecResult(0, "0\n") })
        assertEquals(0, channel.rootUid())
        val result = PageReadDeadline.onWorker(System.nanoTime() - 1L) { channel.runRoot("change-once") }
        assertTrue(result.toString(), result?.timedOut == true)
        assertEquals(1, calls.get())
    }

    @Test fun anExpiredSharedDeadlineDoesNotCreateARealProcess() {
        val pid = temporary.newFile("expired.pid")
        try {
            val result = PageReadDeadline.onWorker(System.nanoTime() - 1L) {
                ProcessSuExec.exec(fixtureArgs("record-only", pid), 2_000L, null)
            }
            assertTrue(result.toString(), result.timedOut)
            assertEquals(0L, pid.length())
        } finally { killFixture(pid) }
    }

    @Test fun aProbeWaiterUsesItsOwnSharedDeadline() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val worker = Executors.newFixedThreadPool(2)
        val channel = UltraSuChannel(exec = { _, _, _ ->
            entered.countDown()
            release.await()
            SuExecResult(0, "0\n")
        })
        try {
            val owner = worker.submit<Int?> { channel.rootUid() }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val waiter = worker.submit<Int?> {
                PageReadDeadline.onWorker(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(20)) { channel.rootUid() }
            }
            assertNull(waiter.get(400, TimeUnit.MILLISECONDS))
            release.countDown()
            assertEquals(0, owner.get(2, TimeUnit.SECONDS))
        } finally { release.countDown(); worker.shutdownNow() }
    }

    @Test fun cleanupFactsNeverCountAsSuccessfulRootEvidence() {
        for (result in listOf(SuExecResult(0, "0\n", cleanupPending = true),
            SuExecResult(0, "0\n", cleanupFailure = "CLOSE_FAILED:IOException"))) {
            val channel = UltraSuChannel(exec = { _, _, _ -> result })
            assertNull(channel.rootUid())
        }
    }

    @Test fun inheritedOutputKeepsCleanupOwnershipWithinTheSharedDeadline() {
        val pid = temporary.newFile("inherited-parent.pid")
        val descendantPid = temporary.newFile("inherited-child.pid")
        val inherited = fixtureArgs("spawn-descendant", pid, *fixtureArgs("hold-output", descendantPid).toTypedArray())
        val started = System.nanoTime()
        try {
            val result = PageReadDeadline.onWorker(started + TimeUnit.MILLISECONDS.toNanos(600)) {
                ProcessSuExec.exec(inherited, 4_000L, null)
            }
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            val failures = buildList {
                if (elapsed >= 1_200L) add("shared600ms elapsed=${elapsed}ms")
                if (result.ok) add("cleanup reported successful SU")
            }
            assertTrue(failures.joinToString("; "), failures.isEmpty())
        } finally {
            awaitPidIfStarted(descendantPid)
            killFixture(descendantPid)
            killFixture(pid)
            awaitCleanupWorkers()
        }
    }

    @Test fun pendingCleanupKeepsAdmissionUntilItsOwnedPipeHasClosed() {
        val release = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val starts = AtomicInteger()
        val process = object : Process() {
            private val output = ByteArrayOutputStream()
            private val input = object : InputStream() {
                private var index = 0
                override fun read(): Int = if (index < 2) "0\n"[index++].code else { release.await(); -1 }
                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    if (length == 0) return 0
                    if (index == 2) { release.await(); return -1 }
                    val count = minOf(length, 2 - index)
                    "0\n".toByteArray().copyInto(buffer, offset, index, index + count)
                    index += count
                    return count
                }
                override fun close() { release.await(); closed.countDown() }
            }
            override fun getOutputStream() = output
            override fun getInputStream() = input
            override fun getErrorStream() = ByteArrayInputStream(ByteArray(0))
            override fun waitFor(): Int = 0
            override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = true
            override fun exitValue(): Int = 0
            override fun destroy() = Unit
        }
        try {
            val started = System.nanoTime()
            val result = PageReadDeadline.onWorker(started + TimeUnit.MILLISECONDS.toNanos(20)) {
                ProcessSuExec.exec(listOf("owned-fixture"), 4_000L, null) { starts.incrementAndGet(); process }
            }
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            val queued = ProcessSuExec.exec(listOf("queued-fixture"), 50, null) { starts.incrementAndGet(); process }
            val failures = buildList {
                if (elapsed >= 1_000L) add("shared20ms elapsed=${elapsed}ms")
                if (!result.cleanupPending) add("pending pipe close was not retained")
                if (result.ok) add("pending cleanup reported successful SU")
                if (!queued.timedOut || starts.get() != 1) add("pending cleanup released admission")
                if (result.exitCode != 0 || result.output != "0\n") add("primary command facts changed")
            }
            assertTrue(failures.joinToString("; "), failures.isEmpty())
        } finally { release.countDown(); assertTrue(closed.await(2, TimeUnit.SECONDS)); awaitCleanupWorkers() }
        val freshPid = temporary.newFile("fresh-after-cleanup.pid")
        val fresh = executeFixture("record-only", freshPid, stdin = null)
        assertTrue("A fresh command must be admitted after the owned pipe closes: $fresh", fresh.ok)
        assertTrue(freshPid.length() > 0L)
    }

    @Test fun startupFailureIncludesErrnoWithoutTheCommandOrPath() {
        val path = File(temporary.root, "private-helper-absent").absolutePath
        val result = ProcessSuExec.exec(listOf(path, "secret-command"), 2_000, null)
        assertTrue(result.failure.orEmpty(), result.failure.orEmpty().matches(Regex("START_FAILED:IOException:errno=[0-9]+")))
        assertFalse(result.failure.orEmpty().contains(path))
        assertFalse(result.failure.orEmpty().contains("secret-command"))
    }

    @Test
    fun timeoutIncludesBlockedStdinAndReapsTheOwnedProcess() {
        val pid = temporary.newFile("blocked.pid")
        // 与其它用例同形：先等宿主 fixture 真的起来（冷 JVM 在满载的主机上可能 >500 ms），
        // 再断言"超时回收"。原先直接 readText() 在满载时会读到空文件而抛
        // NumberFormatException —— 那是用例自身的竞态，不是 ProcessSuExec 的缺陷。
        val worker = Executors.newSingleThreadExecutor()
        try {
            val call = worker.submit<SuExecResult> {
                ProcessSuExec.exec(
                    fixtureArgs("blocked-input", pid),
                    2_000,
                    "x".repeat(2 * 1024 * 1024),
                )
            }
            awaitPid(pid)
            val result = call.get(8, TimeUnit.SECONDS)
            assertTrue(result.timedOut)
            assertFalse(ProcessHandle.of(pid.readText().trim().toLong()).map { it.isAlive }.orElse(false))
        } finally {
            killFixture(pid)
            worker.shutdownNow()
        }
    }

    @Test
    fun outputIsDrainedWhileTheChildIsWaitingForInput() {
        val pid = temporary.newFile("duplex.pid")
        val input = "x".repeat(256 * 1024)
        val result = executeFixture("output-first", pid, stdin = input)
        assertTrue(result.toString(), result.ok)
        assertEquals("o".repeat(256 * 1024) + "\ninput=${input.length}\n", result.output)
    }

    @Test
    fun concurrentCallersDoNotStartCompetingSuProcesses() {
        val workers = Executors.newFixedThreadPool(3)
        val start = CountDownLatch(1)
        val lock = temporary.newFile("single-process.lock")
        val pids = (1..3).map { temporary.newFile("parallel-$it.pid") }
        try {
            val calls = pids.map { pid -> workers.submit<SuExecResult> {
                start.await()
                ProcessSuExec.exec(fixtureArgs("exclusive", pid, lock.absolutePath), 4_000, null)
            } }
            start.countDown()
            calls.forEach { call ->
                val result = call.get(6, TimeUnit.SECONDS)
                assertTrue(result.toString(), result.ok)
            }
        } finally {
            pids.forEach(::killFixture)
            workers.shutdownNow()
        }
    }

    @Test
    fun queueTimeoutDoesNotStartAnotherProcess() {
        val ownerPid = temporary.newFile("owner.pid")
        val queuedPid = temporary.newFile("queued.pid")
        val worker = Executors.newSingleThreadExecutor()
        try {
            val owner = worker.submit<SuExecResult> {
                ProcessSuExec.exec(fixtureArgs("blocked-input", ownerPid), 1_200, null)
            }
            awaitPid(ownerPid)
            val queued = ProcessSuExec.exec(fixtureArgs("blocked-input", queuedPid), 100, null)
            assertTrue(queued.timedOut)
            assertEquals(0L, queuedPid.length())
            assertTrue(owner.get(4, TimeUnit.SECONDS).timedOut)
        } finally {
            killFixture(ownerPid)
            killFixture(queuedPid)
            worker.shutdownNow()
        }
    }

    @Test
    fun interruptionPreservesTheFlagAndReapsTheChild() {
        val pid = temporary.newFile("cancel.pid")
        var result: SuExecResult? = null
        var interrupted = false
        val caller = Thread {
            result = ProcessSuExec.exec(fixtureArgs("blocked-input", pid), 5_000, null)
            interrupted = Thread.currentThread().isInterrupted
        }
        try {
            caller.start()
            awaitPid(pid)
            caller.interrupt()
            caller.join(3_000)
            assertFalse(caller.isAlive)
            assertEquals("EXEC_INTERRUPTED", result?.failure)
            assertTrue(interrupted)
            assertFalse(ProcessHandle.of(pid.readText().trim().toLong()).map { it.isAlive }.orElse(false))
        } finally {
            killFixture(pid)
            caller.interrupt()
            caller.join(2_000)
        }
    }

    @Test
    fun overlappingRootProbesShareOneObservation() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val channel = UltraSuChannel(exec = { _, _, _ ->
            calls.incrementAndGet()
            entered.countDown()
            release.await()
            SuExecResult(0, "0\n")
        })
        var firstUid: Int? = null
        var secondUid: Int? = null
        val first = Thread { firstUid = channel.rootUid() }
        val second = Thread { secondUid = channel.rootUid() }
        try {
            first.start()
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            second.start()
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (second.state !in setOf(Thread.State.BLOCKED, Thread.State.WAITING, Thread.State.TIMED_WAITING) &&
                calls.get() < 2 && System.nanoTime() < until) {
                Thread.yield()
            }
        } finally {
            release.countDown()
            first.join(2_000)
            second.join(2_000)
        }
        assertEquals(0, firstUid)
        assertEquals(0, secondUid)
        assertEquals(1, calls.get())
        assertEquals(0, channel.rootUid())
        assertEquals("A later explicit probe must make a new observation", 2, calls.get())
    }

    @Test
    fun failedCommandInvalidatesThePathWithoutReplayingTheCommand() {
        val calls = mutableListOf<String>()
        val channel = UltraSuChannel(exec = { argv, _, _ ->
            val command = argv.last()
            calls += command
            if (command == "change-once") SuExecResult(-1, "", timedOut = true)
            else SuExecResult(0, if (command == "id -u") "0\n" else "done")
        })
        assertTrue(channel.runRoot("change-once")!!.timedOut)
        assertEquals("done", channel.runRoot("next")?.output)
        assertEquals(listOf("id -u", "change-once", "id -u", "next"), calls)
    }

    @Test
    fun failedRootProbeIsRetriedByTheNextExplicitCall() {
        var available = false
        val channel = UltraSuChannel(exec = { _, _, _ -> SuExecResult(0, if (available) "0\n" else "2000\n") })
        assertNull(channel.rootUid())
        available = true
        assertEquals(0, channel.rootUid())
    }

    @Test
    fun rootTextFromAFailedCommandIsNotSuccessfulPairingEvidence() {
        val channel = UltraSuChannel(exec = { _, _, _ -> SuExecResult(69, "0\n") })
        assertNull(channel.rootUid())
    }

    private fun executeFixture(mode: String, pid: File, stdin: String?, timeout: Long = 3_000): SuExecResult {
        val worker = Executors.newSingleThreadExecutor()
        try {
            return worker.submit<SuExecResult> {
                ProcessSuExec.exec(fixtureArgs(mode, pid), timeout, stdin)
            }.get(5, TimeUnit.SECONDS)
        } finally {
            killFixture(pid)
            worker.shutdownNow()
        }
    }

    private fun fixtureArgs(mode: String, pid: File, vararg extra: String): List<String> {
        val java = File(System.getProperty("java.home"), "bin/java" + if (File.separatorChar == '\\') ".exe" else "").absolutePath
        // Keep the Android test classpath out of Windows' process command-line limit.
        // TemporaryFolder retains each caller's argument file until its child has exited.
        val arguments = File.createTempFile("ultra-su-child-", ".args", temporary.root)
        arguments.writeText((listOf(
            "-cp", System.getProperty("java.class.path"), UltraSuChildFixture::class.java.name, mode, pid.absolutePath,
        ) + extra).joinToString("\n") {
            "\"${it.replace('\\', '/').replace("\"", "\\\"")}\""
        })
        return listOf(java, "@${arguments.absolutePath}")
    }

    private fun killFixture(pid: File) {
        pid.readText().trim().toLongOrNull()?.let { value -> ProcessHandle.of(value).ifPresent { it.destroyForcibly() } }
    }

    private fun awaitPid(pid: File) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (pid.length() == 0L && System.nanoTime() < until) Thread.sleep(5)
        assertTrue("The host fixture did not start", pid.length() > 0L)
    }

    private fun awaitPidIfStarted(pid: File) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (pid.length() == 0L && System.nanoTime() < until) Thread.sleep(5)
    }

    private fun awaitCleanupWorkers() {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (System.nanoTime() < until && Thread.getAllStackTraces().keys.any {
                it.isAlive && it.name in setOf("maplesu-ultra-su-cleanup", "maplesu-ultra-su-reader", "maplesu-ultra-su-writer")
            }) Thread.sleep(5)
    }
}

/** Host-only child process; it never invokes su or touches an Android device. */
object UltraSuChildFixture {
    @JvmStatic
    fun main(args: Array<String>) {
        File(args[1]).writeText(ProcessHandle.current().pid().toString())
        when (args[0]) {
            "spawn-descendant" -> ProcessBuilder(args.drop(2)).inheritIO().start()
            "hold-output" -> { System.out.print("0\n"); System.out.flush(); Thread.sleep(30_000) }
            "blocked-input" -> Thread.sleep(30_000)
            "output-first" -> {
                System.out.print("o".repeat(256 * 1024))
                System.out.flush()
                val input = System.`in`.readBytes()
                System.out.print("\ninput=${input.size}\n")
            }
            "exclusive" -> File(args[2]).outputStream().channel.use { channel ->
                val lock = channel.tryLock() ?: kotlin.system.exitProcess(9)
                lock.use { Thread.sleep(180) }
            }
        }
    }
}
