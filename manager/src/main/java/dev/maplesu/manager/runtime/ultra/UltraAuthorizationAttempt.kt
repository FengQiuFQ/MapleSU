// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

/** One business attempt, including local no-write outcomes and its original SDK receipt. */
internal class UltraAuthorizationAttempt private constructor(
    val error: String?,
    val receipt: NativeReceipt?,
    val readbackMatches: Boolean? = null,
    private val noMutation: Boolean = false,
    val preparation: Preparation? = null,
    /** This invocation's independent UID read; never substitutes for the write receipt. */
    val readReceipt: NativeReceipt? = null,
) {
    val succeeded: Boolean get() = error == null

    /** Only a verified no-op or the original SDK commit receipt proves a decision. */
    val decisionCommitted: Boolean get() =
        (noMutation && succeeded && readbackMatches == true) ||
            receipt?.authorizationResult?.let { it.operationResultAvailable && it.commitState == 2L } == true

    /** Membership readback is independent of whether the traditional entry opened. */
    val decisionVerified: Boolean get() = readbackMatches == true

    val pendingApply: Boolean get() = decisionCommitted && (!succeeded || !decisionVerified)

    val commitUnknown: Boolean get() = receipt != null && !decisionCommitted &&
        receipt.authorizationResult.let { it == null || !it.operationResultAvailable || it.commitState == 0L }

    data class Preparation(val attempted: Boolean?, val installed: Boolean?, val reason: String,
                           val blockedCode: String? = null) {
        val diagnosticSummary: String get() =
            "preparationAttempted=$attempted preparationInstalled=$installed " +
                "preparation=${suAuthLogCode(reason)} blocked=${blockedCode?.let(::suAuthLogCode) ?: "none"}"
    }

    fun withReadReceipt(value: NativeReceipt?): UltraAuthorizationAttempt =
        UltraAuthorizationAttempt(error, receipt, readbackMatches, noMutation, preparation, value)

    fun withPreparation(value: Preparation): UltraAuthorizationAttempt =
        UltraAuthorizationAttempt(error, receipt, readbackMatches, noMutation, value, readReceipt)

    fun withReadback(matches: Boolean, noMutation: Boolean = false): UltraAuthorizationAttempt =
        UltraAuthorizationAttempt(error, receipt, matches, noMutation, preparation, readReceipt)

    /** A failed readback adds a business failure without replacing the SDK evidence. */
    fun withFailure(error: String): UltraAuthorizationAttempt =
        if (this.error != null) this
        else UltraAuthorizationAttempt(error, receipt, readbackMatches, noMutation, preparation, readReceipt)

    val diagnosticSummary: String
        get() = buildString {
            append(receipt?.authorizationDiagnosticSummary() ?: "sdkReceipt=false")
            readReceipt?.takeUnless { it === receipt }?.let {
                append(" readReceipt=[").append(it.authorizationDiagnosticSummary()).append(']')
            }
            append(" business=${error?.let(::suAuthLogCode) ?: "OK"}")
            append(" decisionCommitted=$decisionCommitted decisionVerified=$decisionVerified")
            append(" pendingApply=$pendingApply commitUnknown=$commitUnknown readbackMatches=$readbackMatches")
            preparation?.let { append(' ').append(it.diagnosticSummary) }
        }

    companion object {
        fun from(receipt: NativeReceipt): UltraAuthorizationAttempt =
            UltraAuthorizationAttempt(receipt.suAuthWriteError().takeUnless { it == "OK" }, receipt)

        fun local(error: String? = null): UltraAuthorizationAttempt = UltraAuthorizationAttempt(error, null)
    }
}

private val SU_AUTH_LOG_CODE = Regex("[A-Za-z0-9_():-]{1,128}")

/** SDK error names are untrusted text; diagnostics accept machine codes only. */
internal fun suAuthLogCode(value: String): String =
    UltraSdkLogging.redact(value).takeIf { SU_AUTH_LOG_CODE.matches(it) } ?: "UNRECOGNIZED"

/** Explicit scalar projection; never log raw/data/reason or the receipt's default toString. */
internal fun NativeReceipt.authorizationDiagnosticSummary(): String = UltraSdkLogging.redact(buildString {
    append("sdkReceipt=true ok=$ok sdk=${suAuthLogCode(sdkError)} code=$sdkErrorCode")
    val detail = authorizationResult
    append(" detail=${detail != null}")
    if (detail != null) {
        append(" available=${detail.operationResultAvailable} operation=${detail.operation}")
        append(" result=${detail.resultCode} primary=${detail.primaryErrorCode} phase=${detail.primaryPhase}")
        append(" recovery=[")
        append(detail.recovery?.joinToString(",") { "${it.phase}:${it.errorCode}" } ?: "unknown")
        append("] total=${detail.recoveryTotal} complete=${detail.diagnosticsComplete}")
        append(" commit=${detail.commitState} restore=${detail.restoreState} delivery=${detail.deliveryState}")
        val transport = detail.transport
        append(" transport=${transport.status} errno=${transport.errno}")
        append(" childWait=${transport.childWaitStatus} transportValid=${transport.valid}")
    }
    if (data?.has("uidReadResult") == true) append(' ').append(uidReadDiagnosticSummary())
})
