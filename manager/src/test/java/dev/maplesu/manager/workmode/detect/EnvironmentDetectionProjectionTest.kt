// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.detect

import android.os.Process
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.activeMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * T14：环境结论 → 启动判定覆盖（纯映射）。
 *
 * 当前完整 Ultra owner 仅投影已安装未绑定；历史 LITE 和 UNKNOWN 保持未授能力。
 */
class EnvironmentDetectionProjectionTest {

    private fun outcome(
        verdict: EnvironmentVerdict,
        mode: WorkMode?,
        trigger: EnvironmentCheckTrigger? = EnvironmentCheckTrigger.NO_STATE,
        detail: String = "TEST",
        bootId: String = "boot-1",
        owner: UltraRuntimeClient.ManagerOwnerIdentity? = null,
    ) = EnvironmentCheckOutcome(
        verdict = verdict,
        mode = mode,
        snapshot = null,
        trigger = trigger,
        detail = detail,
        bootId = bootId,
        elapsedMillis = 12L,
        probes = listOf("su", "ultra"),
        ultraOwnerIdentity = owner,
    )

    @Test
    fun ksuNormalActivatesKsuWithoutRootEvidence() {
        val detection = EnvironmentDetectionProjection.override(
            outcome(EnvironmentVerdict.KSU_NORMAL, WorkMode.KSU),
            observedAtMillis = 99L,
        )
        assertNotNull(detection)
        assertEquals(ModeState.MODE_B_KERNEL_ONLY, detection?.state)
        assertEquals(WorkMode.KSU, detection?.state?.activeMode)
        assertEquals("boot-1", detection?.bootId)
        assertEquals(99L, detection?.observedAtMillis)
        assertEquals(EnvironmentDetectionProjection.TRACE_ID, detection?.trace?.firstOrNull()?.id)
        assertNull("前置覆盖不得声称已开 root 通道", detection?.rootChannel)
    }

    @Test
    fun notInstalledIsTerminalWithoutAnyMode() {
        val detection = EnvironmentDetectionProjection.override(
            outcome(EnvironmentVerdict.NOT_INSTALLED, null, detail = EnvironmentCheckDetail.SU_ABSENT_NO_ULTRA),
        )
        assertNotNull(detection)
        assertEquals(ModeState.NOT_INSTALLED, detection?.state)
        assertNull(detection?.state?.activeMode)
    }

    @Test
    fun inheritedStatesNeverGrantCurrentIdentityOrAbsence() {
        for (mode in listOf(WorkMode.KSU, WorkMode.LITE, null)) {
            assertNull("History is display data only: $mode", EnvironmentDetectionProjection.override(
                outcome(EnvironmentVerdict.INHERITED, mode, trigger = null),
            ))
        }
    }

    @Test
    fun ultraAndUnknownNeverOverride() {
        assertNull(
            EnvironmentDetectionProjection.override(outcome(EnvironmentVerdict.ULTRA, WorkMode.LITE)),
        )
        assertNull(
            EnvironmentDetectionProjection.override(
                outcome(EnvironmentVerdict.UNKNOWN, null, detail = EnvironmentCheckDetail.DEADLINE_EXCEEDED),
            ),
        )
    }

    @Test
    fun currentUltraOwnerOnlyProjectsInstallationWithoutAnActiveModeOrRoot() {
        val owner = UltraRuntimeClient.ManagerOwnerIdentity(Process.myUid(), 7, "ab".repeat(16))
        val detection = EnvironmentDetectionProjection.override(
            outcome(EnvironmentVerdict.ULTRA, WorkMode.LITE, owner = owner),
        )
        assertEquals(ModeState.MODE_A_INSTALLED_UNBOUND, detection?.state)
        assertEquals(DetectionRules.Rule.R6_A_ULTRA_OWNER_ONLY, detection?.rule)
        assertNull(detection?.state?.activeMode)
        assertNull(detection?.rootChannel)
        assertEquals(RecoveryReadiness.NONE, detection?.recovery)
    }

    @Test
    fun anOwnerFieldDoesNotPromoteUnknownOrInheritedHistory() {
        val owner = UltraRuntimeClient.ManagerOwnerIdentity(Process.myUid(), 7, "ab".repeat(16))
        assertNull(EnvironmentDetectionProjection.override(
            outcome(EnvironmentVerdict.UNKNOWN, WorkMode.LITE, owner = owner),
        ))
        assertNull(EnvironmentDetectionProjection.override(
            outcome(EnvironmentVerdict.INHERITED, WorkMode.LITE, trigger = null, owner = owner),
        ))
    }
}
