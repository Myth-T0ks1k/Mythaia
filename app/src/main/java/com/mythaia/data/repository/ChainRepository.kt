package com.mythaia.data.repository

import android.content.Context
import com.mythaia.data.model.ProxyChain
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.util.UUID

class ChainRepository(context: Context) {
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }
    private val file = File(context.filesDir, "chains.json")

    private val _chains = MutableStateFlow<List<ProxyChain>>(emptyList())
    val chains: StateFlow<List<ProxyChain>> = _chains.asStateFlow()

    init {
        _chains.value = loadFromDisk()
    }

    fun getAll(): List<ProxyChain> = _chains.value

    fun get(id: UUID): ProxyChain? = _chains.value.find { it.id == id }

    fun add(chain: ProxyChain) {
        _chains.update { it + chain }
        saveToDisk()
    }

    fun update(chain: ProxyChain) {
        _chains.update { list -> list.map { if (it.id == chain.id) chain else it } }
        saveToDisk()
    }

    fun delete(id: UUID) {
        _chains.update { list -> list.filter { it.id != id } }
        saveToDisk()
    }

    private fun loadFromDisk(): List<ProxyChain> {
        if (!file.exists()) return emptyList()
        return runCatching {
            json.decodeFromString<List<ProxyChain>>(file.readText())
        }.getOrElse {
            com.mythaia.vpn.util.MythaiaLogger("ChainStore").error("Failed to load chains: $it")
            file.quarantineCorrupt()
            emptyList()
        }
    }

    private fun saveToDisk() {
        val payload = json.encodeToString(_chains.value)
        file.writeTextAsync(payload) {
            com.mythaia.vpn.util.MythaiaLogger("ChainStore").error("Failed to save chains: $it")
        }
    }

    companion object {
        @Volatile
        private var instance: ChainRepository? = null

        /**
         * The one instance for this process. The tile, the watch and the view
         * model all read chains; with an instance each, a chain just created
         * in the UI is not yet on disk when the tile asks for it.
         */
        fun get(context: Context): ChainRepository =
            instance ?: synchronized(this) {
                instance ?: ChainRepository(context.applicationContext).also { instance = it }
            }
    }
}
