package dev.maplesu.manager.workmode.detect.probes

import org.junit.Assert.*
import org.junit.Test

class ForeignKsuProbeTest {
    @Test fun aDistinctCurrentKernelBranchAndNonManagerFlagConfirmAForeignKernel() {
        assertEquals(true, ForeignKsuProbe.parseResponse("version: 10940\nflags: 0x1\nuapi_version: 6\n"))
        assertEquals(true, ForeignKsuProbe.parseResponse("version: 32650\nflags: 0x0\nuapi_version: 8\n"))
    }
    @Test fun recognizedManagerIsNotAForeignKernel() {
        assertNull(ForeignKsuProbe.parseResponse("version: 10940\nflags: 0x2\n"))
    }
    @Test fun versionAloneAndUserspaceVersionNeverExcludeTheManager() {
        assertNull(ForeignKsuProbe.parseResponse("version: 10940\n"))
        assertNull(ForeignKsuProbe.parseResponse("userspace_version: 10940\nflags: 0x0\n"))
    }
    @Test fun ourBranchWithoutManagerOwnershipIsNotAForeignModeReceipt() {
        assertNull(ForeignKsuProbe.parseResponse("version: 32650\nflags: 0x0\nuapi_version: 7\n"))
    }
    @Test fun aLegacyOrMissingKernelBranchDoesNotExcludeOurCompatibilityMode() {
        assertNull(ForeignKsuProbe.parseResponse("version: 10940\nflags: 0x0\nuapi_version: 0\n"))
        assertNull(ForeignKsuProbe.parseResponse("version: 10940\nflags: 0x1\n"))
        assertNull(ForeignKsuProbe.parseResponse("version: 10940\nflags: 0x0\nuserspace_uapi_version: 8\n"))
    }
    @Test fun nonRespondingKernelIsNotPositiveEvidence() {
        assertNull(ForeignKsuProbe.parseResponse("version: 0\nflags: 0x0\nuapi_version: 6\n"))
        assertNull(ForeignKsuProbe.parseResponse("not available"))
    }
}
