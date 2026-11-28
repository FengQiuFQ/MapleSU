package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.BoundedPageRead
import dev.maplesu.manager.runtime.PageReadDeadline
import java.io.File
import java.lang.reflect.Modifier
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.TimeoutException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

/** Real page single-flight and SDK admission; only the JNI answer is substituted. */
class ForegroundPageLoadTest {
    private fun client(): UltraRuntimeClient {
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply {
            isAccessible = true
        }.get(null) as sun.misc.Unsafe
        return unsafe.allocateInstance(UltraRuntimeClient::class.java) as UltraRuntimeClient
    }

    private fun call(client: UltraRuntimeClient, operation: String, body: () -> String?): NativeReceipt {
        val method = UltraRuntimeClient::class.java.getDeclaredMethod("call", String::class.java, Function0::class.java)
            .apply { isAccessible = true }
        return method.invoke(client, operation, body) as NativeReceipt
    }

    private fun answer(operation: String, count: Int) = """{
        "backend":"maplesu_ultra","operation":"$operation","ok":true,"sdkError":"OK",
        "sdkErrorCode":0,"data":{"count":$count}}
    """

    @Test fun bothColdPagesReadOnceAfterStartupReleasesTheSdkWithinThePageBudget() = runBlocking {
        val entered = CountDownLatch(1)
        val pagesStarted = CountDownLatch(2)
        val release = CountDownLatch(1)
        val submitted = AtomicInteger()
        val operations = ConcurrentHashMap<String, AtomicInteger>()
        val workers = Executors.newFixedThreadPool(2)
        val client = client()
        try {
            val startup = workers.submit<NativeReceipt> {
                call(client, "run_root_cmd") {
                    entered.countDown()
                    check(release.await(8, TimeUnit.SECONDS))
                    answer("run_root_cmd", 0)
                }
            }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val modules = BoundedPageRead<NativeReceipt>(4_000)
            val authorizations = BoundedPageRead<NativeReceipt>(4_000)
            val moduleRead = async(Dispatchers.IO) {
                modules.read("LITE") {
                    pagesStarted.countDown()
                    // listModules reads the SDK catalog, then the root-backed KSU tree.
                    val catalog = call(client, "get_all_modules_list") {
                        submitted.incrementAndGet()
                        operations.computeIfAbsent("get_all_modules_list") { AtomicInteger() }.incrementAndGet()
                        answer("get_all_modules_list", 1)
                    }
                    check(catalog.succeeded) { catalog.sdkError }
                    call(client, "run_root_cmd") {
                        submitted.incrementAndGet()
                        operations.computeIfAbsent("run_root_cmd") { AtomicInteger() }.incrementAndGet()
                        answer("run_root_cmd", 51)
                    }
                }
            }
            val authorizationRead = async(Dispatchers.IO) {
                authorizations.read("LITE") {
                    pagesStarted.countDown()
                    // UltraAppListSnapshot starts its SDK work in a separate IO child.
                    coroutineScope {
                        async(Dispatchers.IO) {
                            call(client, "get_su_auth_list") {
                                submitted.incrementAndGet()
                                operations.computeIfAbsent("get_su_auth_list") { AtomicInteger() }.incrementAndGet()
                                answer("get_su_auth_list", 4)
                            }
                        }.await()
                    }
                }
            }
            val startupComplete = workers.submit {
                check(pagesStarted.await(2, TimeUnit.SECONDS))
                Thread.sleep(1_800)
                release.countDown()
            }
            val repeatedPageRequests = (1..8).flatMap {
                listOf(
                    async { modules.read("LITE") { error("Module query was duplicated") } },
                    async { authorizations.read("LITE") { error("Authorization query was duplicated") } },
                )
            }
            val results = listOf(moduleRead.await(), authorizationRead.await())
            repeatedPageRequests.forEach { assertTrue(it.await().succeeded) }
            assertTrue("Cold page failed before startup completed: ${results.map { it.sdkError }}",
                results.all { it.succeeded })
            assertEquals(51, results[0].int("count"))
            assertEquals(4, results[1].int("count"))
            assertEquals("Neither page may be replayed", 3, submitted.get())
            assertEquals(mapOf("get_all_modules_list" to 1, "run_root_cmd" to 1, "get_su_auth_list" to 1),
                operations.mapValues { it.value.get() })
            startupComplete.get(3, TimeUnit.SECONDS)
            assertTrue(startup.get(2, TimeUnit.SECONDS).succeeded)
        } finally {
            release.countDown()
            workers.shutdownNow()
            workers.awaitTermination(3, TimeUnit.SECONDS)
        }
    }

    @Test fun expiredPageNeverSubmitsALateSdkCallAndDoesNotLeakItsDeadline() = runBlocking {
        val release = CountDownLatch(1)
        val completed = CountDownLatch(1)
        val late = AtomicReference<NativeReceipt>()
        val submitted = AtomicInteger()
        val client = client()
        try {
            val page = BoundedPageRead<NativeReceipt>(100)
            try {
                page.read("LITE") {
                    try {
                        check(release.await(4, TimeUnit.SECONDS))
                        call(client, "get_all_modules_list") {
                            submitted.incrementAndGet()
                            answer("get_all_modules_list", 51)
                        }.also { late.set(it) }
                    } finally { completed.countDown() }
                }
                fail("The original page deadline must still end the spinner")
            } catch (_: TimeoutException) { }
            release.countDown()
            assertTrue(completed.await(2, TimeUnit.SECONDS))
            val receipt = late.get()
            assertEquals("MAPLESU_SDK_DEADLINE_EXCEEDED", receipt.sdkError)
            assertEquals(-1007, receipt.sdkErrorCode)
            val raw = org.json.JSONObject(receipt.raw)
            assertEquals(receipt.sdkError, raw.getString("sdkError"))
            assertEquals(receipt.sdkErrorCode, raw.getInt("sdkErrorCode"))
            assertEquals(0, submitted.get())
            assertNull(PageReadDeadline.currentNanos())
            assertTrue(call(client, "get_su_auth_list") { answer("get_su_auth_list", 4) }.succeeded)
        } finally { release.countDown() }
    }

    @Test fun invalidationRereadKeepsTheOriginalPageDeadline() = runBlocking {
        val page = BoundedPageRead<String>(2_000)
        val deadlines = mutableListOf<Long?>()
        var calls = 0
        assertEquals("fresh", page.read("LITE") {
            deadlines += PageReadDeadline.currentNanos()
            if (++calls == 1) { page.invalidate(); "stale" } else "fresh"
        })
        assertEquals(2, calls)
        assertNotNull(deadlines[0])
        assertEquals(deadlines[0], deadlines[1])
    }

    @Test fun verifiedUltraListRoutingDoesNotRequireASecondEnvironmentProbe() {
        val source = File("src/main/java/com/maplesu/core/data/repository/SuperUserRepositoryImpl.kt").readText()
        val gate = source.substringAfter("private fun usesReadyUltraBackend(): Boolean {")
            .substringBefore("private suspend fun loadLiteAppList()")
        val knownSdk = gate.indexOf("if (UltraEnvironmentProbe.usesUltraBackend(ksuApp)) return true")
        val probe = gate.indexOf("UltraEnvironmentProbe.refresh(")
        assertTrue("An established SDK identity must select the read-only backend before a competing cold probe", knownSdk >= 0 && probe > knownSdk)
    }

    @Test fun independentInventoryNeverWaitsOnTheLongRunningScriptMonitor() {
        val runner = Class.forName("dev.maplesu.manager.modules.ManagementModuleScriptRunner")
        val snapshot = runner.getDeclaredMethod("readSnapshot", String::class.java)
        assertFalse("Inventory uses independent SDK admission, not the streaming script monitor", Modifier.isSynchronized(snapshot.modifiers))
        assertTrue("Streaming mutations still serialize their shell session",
            Modifier.isSynchronized(runner.getDeclaredMethod("run", String::class.java).modifiers))
    }
}
