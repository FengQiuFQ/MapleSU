package com.maplesu.core.ui.viewmodel

import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

internal const val SUPERUSER_PAGE_TIMEOUT_MILLIS = 10_000L

/** Wait for the actual mode gate; a loading preview never selects a backend. */
internal class SuperuserStartupLoader(
    private val currentMode: () -> WorkMode?,
    private val awaitMode: suspend () -> WorkMode?,
) {
    /** The caller's earlier deadline covers waiting and every stage of the actual load. */
    suspend fun load(
        onWaiting: () -> Unit,
        load: suspend (WorkMode) -> Unit,
    ): Boolean = withContext(PageReadDeadline.context(SUPERUSER_PAGE_TIMEOUT_MILLIS)) {
        val remaining = ((requireNotNull(PageReadDeadline.currentNanos()) - System.nanoTime()) / 1_000_000L)
            .coerceAtLeast(0L)
        withTimeout(remaining) {
            val mode = currentMode() ?: run {
                onWaiting()
                awaitMode()
            } ?: return@withTimeout false
            currentCoroutineContext().ensureActive()
            load(mode)
            currentCoroutineContext().ensureActive()
            true
        }
    }
}
