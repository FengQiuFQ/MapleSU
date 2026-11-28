package dev.maplesu.manager.workmode.detect.probes

import dev.maplesu.manager.ksu.KsuBackends
import dev.maplesu.manager.workmode.detect.KsuFacts
import dev.maplesu.manager.workmode.detect.KsuKernelProbe

/**
 * KSU 内核探针适配器（取值来源为同树 JNI `KsuNatives` 与后端门面）。
 *
 * 接线（W04b）：`manager/src/ksu/java/.../KsuNatives.kt`（main sourceSet，见
 * `manager/build.gradle.kts:61`）。**只走安全调用层** [KsuBackends.natives]：
 * native 未加载 / 符号缺失 / 结构失败 → `available=false`，抛出固定探针异常，
 * 由探测器保留 S1/S2 unknown；不把映射默认值写成"没有 KSU"。
 *
 * 映射是纯函数 [KsuProbeMapping]（主机可测）；真机路径只负责取一次快照。
 */
object KsuKernelProbeAdapter : KsuKernelProbe {
    override fun probe(): KsuFacts {
        val snapshot = currentSnapshot()
        check(snapshot.available && snapshot.status == 0 && snapshot.version > 0) {
            "KSU_PROBE_UNAVAILABLE:${snapshot.status}"
        }
        return KsuProbeMapping.from(snapshot)
    }

    /** 一次 native 只读快照；任何异常 → unavailable（unknown）。 */
    internal fun currentSnapshot(): KsuNativeSnapshot = runCatching {
        val natives = KsuBackends.natives()
        if (natives.available) KsuNativeSnapshot.fromCurrentInfo(natives.currentInfo())
        else KsuNativeSnapshot.UNAVAILABLE
    }.getOrDefault(KsuNativeSnapshot.UNAVAILABLE)
}

/** native 侧只读快照（与 libsu/JNI 解耦，便于主机测试）。 */
data class KsuNativeSnapshot(
    val available: Boolean,
    val version: Int,
    val kernelUapi: Int,
    val isManager: Boolean,
    val isLkm: Boolean,
    val status: Int = 0,
) {
    companion object {
        /** All fields belong to one current native GET_INFO operation. */
        fun fromCurrentInfo(info: IntArray?): KsuNativeSnapshot {
            if (info == null || info.size != 4) return UNAVAILABLE
            return KsuNativeSnapshot(true, info[1], info[3],
                info[0] == 0 && info[2] and 2 != 0,
                info[0] == 0 && info[2] and 1 != 0, info[0])
        }

        val UNAVAILABLE = KsuNativeSnapshot(
            available = false,
            version = -1,
            kernelUapi = -1,
            isManager = false,
            isLkm = false,
        )
    }
}

/**
 * 快照 → [KsuFacts] 的**纯映射**：
 * - native 不可用 → 全 unknown（`KsuFacts()` 默认值，version=-1）；
 * - 当前操作失败或版本 <= 0 → unknown，不透传其它身份或能力字段；
 * - 可用且版本 > 0 → `responded=true`，uapi/isManager/isLkm 原样透传。
 */
object KsuProbeMapping {
    /** A hidden/unclaimed build branch or the legacy compatibility ABI is still unknown. */
    fun normalStatus(snapshot: KsuNativeSnapshot): Boolean? {
        if (!snapshot.available || snapshot.status != 0 || snapshot.version <= 0) return null
        if (snapshot.isManager) return true
        if (snapshot.kernelUapi <= 0 || snapshot.kernelUapi == 7) return null
        return false
    }

    fun from(snapshot: KsuNativeSnapshot): KsuFacts {
        if (!snapshot.available || snapshot.status != 0 || snapshot.version <= 0) return KsuFacts()
        return KsuFacts(
            responded = snapshot.version > 0,
            version = snapshot.version,
            uapi = snapshot.kernelUapi,
            isManager = snapshot.isManager,
            isLkm = snapshot.isLkm,
        )
    }
}
