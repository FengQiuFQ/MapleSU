package dev.maplesu.manager.workmode.detect.probes

import dev.maplesu.manager.workmode.detect.KsuFacts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 探针 unknown 语义：native 不可用/版本不可读时不得造数据（02 §3.9、01 §2.7）。 */
class KsuProbeMappingTest {
    @Test
    fun fastNormalProbeRequiresManagerOwnershipLikeFullDetection() {
        val owned = KsuNativeSnapshot(true, 32650, 7, true, true)
        assertEquals(true, KsuProbeMapping.normalStatus(owned))
        assertEquals(null, KsuProbeMapping.normalStatus(owned.copy(isManager = false)))
        assertEquals(null, KsuProbeMapping.normalStatus(owned.copy(isManager = false, kernelUapi = -1)))
        assertEquals(false, KsuProbeMapping.normalStatus(owned.copy(isManager = false, kernelUapi = 6)))
        assertEquals(null, KsuProbeMapping.normalStatus(owned.copy(version = 0)))
        assertEquals(null, KsuProbeMapping.normalStatus(owned.copy(version = -1)))
        assertEquals(null, KsuProbeMapping.normalStatus(KsuNativeSnapshot.UNAVAILABLE))
    }

    @Test
    fun ultraCompatibilityVersionDoesNotEstablishNormalOwnership() {
        // manager_ksu_compat.c GET_INFO exposes 10940 with flags=0 and uapi=0.
        val compatible = KsuNativeSnapshot(true, 10940, 0, false, false)
        assertTrue(KsuProbeMapping.from(compatible).responded)
        assertFalse(KsuProbeMapping.from(compatible).isManager)
        assertEquals(null, KsuProbeMapping.normalStatus(compatible))
    }

    @Test
    fun unavailableSnapshotIsUnknown() {
        val facts = KsuProbeMapping.from(KsuNativeSnapshot.UNAVAILABLE)
        assertEquals(KsuFacts(), facts)
        assertFalse(facts.responded)
        assertEquals(-1, facts.version)
        assertEquals(-1, facts.uapi)
        assertFalse(facts.isManager)
        assertFalse(facts.isLkm)
    }

    @Test
    fun availableZeroVersionIsNotResponded() {
        val facts = KsuProbeMapping.from(
            KsuNativeSnapshot(available = true, version = 0, kernelUapi = 7, isManager = true, isLkm = true),
        )
        assertFalse(facts.responded)
        assertEquals(KsuFacts(), facts)
    }

    @Test
    fun activeKernelMapsAllFields() {
        val facts = KsuProbeMapping.from(
            KsuNativeSnapshot(available = true, version = 32650, kernelUapi = 7, isManager = true, isLkm = true),
        )
        assertTrue(facts.responded)
        assertEquals(32650, facts.version)
        assertEquals(7, facts.uapi)
        assertTrue(facts.isManager)
        assertTrue(facts.isLkm)
    }

    @Test
    fun nonManagerKernelStillResponded() {
        val facts = KsuProbeMapping.from(
            KsuNativeSnapshot(available = true, version = 32650, kernelUapi = 7, isManager = false, isLkm = false),
        )
        assertTrue(facts.responded)
        assertFalse(facts.isManager)
    }

    @Test
    fun unavailableIsNotFabricatedAsForeign() {
        // unknown 的 version/uapi=-1 不得被当成"外来内核"证据；由 DetectionRules 的
        // responded=false 分支保证（R4 需要 responded）。
        assertEquals(-1, KsuProbeMapping.from(KsuNativeSnapshot.UNAVAILABLE).uapi)
        assertFalse(KsuProbeMapping.from(KsuNativeSnapshot.UNAVAILABLE).responded)
    }

    @Test
    fun aSingleNativeReceiptBindsVersionOwnershipAndAbi() {
        val current = KsuNativeSnapshot.fromCurrentInfo(intArrayOf(0, 32650, 3, 7))
        assertEquals(true, KsuProbeMapping.normalStatus(current))
        assertEquals(KsuFacts(true, 32650, 7, true, true), KsuProbeMapping.from(current))
        val revoked = KsuNativeSnapshot.fromCurrentInfo(intArrayOf(0, 32650, 1, 7))
        assertEquals(null, KsuProbeMapping.normalStatus(revoked))
        assertFalse(KsuProbeMapping.from(revoked).isManager)
    }

    @Test
    fun deniedOrMalformedCurrentReceiptsDoNotReusePositiveFields() {
        for (receipt in listOf(null, intArrayOf(), intArrayOf(0, 32650, 3),
            intArrayOf(-13, 32650, 3, 7), intArrayOf(-9, 0, 0, 0), intArrayOf(0, 0, 3, 7))) {
            val current = KsuNativeSnapshot.fromCurrentInfo(receipt)
            assertEquals(null, KsuProbeMapping.normalStatus(current))
            assertEquals(KsuFacts(), KsuProbeMapping.from(current))
        }
    }
}
