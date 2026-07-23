package org.vaultkern.core

import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private fun copyAndClear(value: ByteArray): ByteArray = try {
    value.copyOf()
} finally {
    value.fill(0)
}

/**
 * Clearable text storage for secret-bearing UniFFI DTO fields.
 *
 * `reveal()` necessarily creates a JVM String for rendering or an FFI call;
 * callers should keep that value short-lived and call `close()` on this owner.
 */
public class VaultKernSensitiveString private constructor(
    private var bytes: ByteArray,
) : AutoCloseable {
    private val lock = ReentrantLock()

    public companion object {
        @JvmStatic
        public fun fromString(value: String): VaultKernSensitiveString =
            VaultKernSensitiveString(value.toByteArray(Charsets.UTF_8))

        @JvmStatic
        public fun fromUtf8Bytes(value: ByteArray): VaultKernSensitiveString {
            return VaultKernSensitiveString(copyAndClear(value))
        }
    }

    public fun reveal(): String = lock.withLock { bytes.toString(Charsets.UTF_8) }

    public fun copyUtf8Bytes(): ByteArray = lock.withLock { bytes.copyOf() }

    override fun close() {
        lock.withLock {
            bytes.fill(0)
            bytes = ByteArray(0)
        }
    }

    override fun toString(): String = "[REDACTED]"
}

/** Clearable bytes used only while crossing the protected-storage adapter. */
public class VaultKernSensitiveBytes private constructor(
    private var bytes: ByteArray,
) : AutoCloseable {
    private val lock = ReentrantLock()

    public companion object {
        @JvmStatic
        public fun fromByteArray(value: ByteArray): VaultKernSensitiveBytes {
            return VaultKernSensitiveBytes(copyAndClear(value))
        }
    }

    public fun copyBytes(): ByteArray = lock.withLock { bytes.copyOf() }

    override fun close() {
        lock.withLock {
            bytes.fill(0)
            bytes = ByteArray(0)
        }
    }

    override fun toString(): String = "VaultKernSensitiveBytes([REDACTED])"
}
