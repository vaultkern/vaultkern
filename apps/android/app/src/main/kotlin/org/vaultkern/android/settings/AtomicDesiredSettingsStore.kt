package org.vaultkern.android.settings

import android.content.Context
import android.util.AtomicFile
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileNotFoundException

class AtomicDesiredSettingsStore(
    context: Context,
    directoryName: String = "settings",
) : DesiredSettingsStore {
    private val directory = File(context.noBackupFilesDir, directoryName)
    private val file = AtomicFile(File(directory, FILE_NAME))
    private val gate = Any()

    override fun load(): AndroidDesiredSettings = synchronized(gate) {
        val input = try {
            file.openRead()
        } catch (_: FileNotFoundException) {
            return@synchronized AndroidDesiredSettings()
        }
        DataInputStream(input.buffered()).use { data ->
            require(data.readInt() == MAGIC) { "unsupported Android settings format" }
            require(data.readUnsignedByte() == VERSION) { "unsupported Android settings version" }
            AndroidDesiredSettings(quickUnlockEnabled = data.readBoolean())
        }
    }

    override fun save(settings: AndroidDesiredSettings) = synchronized(gate) {
        check(directory.mkdirs() || directory.isDirectory) {
            "Android settings directory is unavailable"
        }
        val output = file.startWrite()
        try {
            DataOutputStream(output.buffered()).use { data ->
                data.writeInt(MAGIC)
                data.writeByte(VERSION)
                data.writeBoolean(settings.quickUnlockEnabled)
                data.flush()
                file.finishWrite(output)
            }
        } catch (error: Throwable) {
            file.failWrite(output)
            throw error
        }
    }

    companion object {
        private const val FILE_NAME = "desired-state.bin"
        private const val MAGIC = 0x564B4153
        private const val VERSION = 1
    }
}
