package dev.maplesu.manager.workmode.detect

import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.workmode.detect.probes.ultraRecoveryFingerprint
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/**
 * "整条 SDK 通道都没应答" ≠ "探针读失败"。
 *
 * 前者是这台机器上没有可读的 MapleSU 环境（没装 helper、内核也没有 MapleSU 桥），
 * 必须让判定继续往下走，否则装了第三方 KernelSU 的机器永久停在「环境检查未完成」；
 * 后者仍然抛错，resolver 会保留 UNKNOWN 而不是落成"未安装"。
 */
class UltraRecoveryFingerprintVerdictTest {

    @Test fun anAbsentChannelIsNotAUltraEnvironment() {
        assertNull(
            ultraRecoveryFingerprint(
                state = UltraEnvironmentProbe.State.Unknown,
                safeMode = false,
                kernelRootVerified = false,
                kernelChannelAbsent = false,
                sdkChannelAvailable = false,
            ),
        )
    }

    @Test fun aReadableChannelStillReportsThatItCannotDecide() {
        try {
            ultraRecoveryFingerprint(
                state = UltraEnvironmentProbe.State.Unknown,
                safeMode = false,
                kernelRootVerified = false,
                kernelChannelAbsent = false,
                sdkChannelAvailable = true,
            )
            fail("a readable channel that cannot decide must stay UNKNOWN, not become 'not installed'")
        } catch (expected: IllegalStateException) {
            assertEquals("ULTRA_RECOVERY_PROBE_UNKNOWN", expected.message)
        }
    }

    @Test fun explicitKernelPresenceAndVerifiedKernelRootKeepTheirMeaning() {
        // 内核明确回 ERR_MODULE_NO_BOOT：没有 Ultra 环境。
        assertNull(
            ultraRecoveryFingerprint(
                state = UltraEnvironmentProbe.State.Unknown,
                safeMode = false,
                kernelRootVerified = false,
                kernelChannelAbsent = true,
                sdkChannelAvailable = false,
            ),
        )
        // 通道应答过且 root 已验证：这是"内核在，装环境去"。
        assertEquals(
            "ultra:kernel",
            ultraRecoveryFingerprint(
                state = UltraEnvironmentProbe.State.Unknown,
                safeMode = false,
                kernelRootVerified = true,
                kernelChannelAbsent = false,
                sdkChannelAvailable = true,
            ),
        )
    }

    @Test fun otherRecoveryFailuresStillPropagate() {
        try {
            ultraRecoveryFingerprint(
                state = UltraEnvironmentProbe.State.NoKey,
                safeMode = false,
                kernelRootVerified = false,
                kernelChannelAbsent = false,
                sdkChannelAvailable = false,
            )
            fail("a missing identity key is a real read failure")
        } catch (expected: IllegalStateException) {
            assertEquals("ULTRA_RECOVERY_IDENTITY_UNKNOWN", expected.message)
        }
    }
}
