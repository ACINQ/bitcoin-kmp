package fr.acinq.bitcoin

fun fixSize(data: ByteArray, size: Int): ByteArray = when {
    data.size == size -> data
    data.size < size -> ByteArray(size - data.size) + data
    else -> {
        throw RuntimeException("overflow")
    }
}

fun <T> List<T>.updated(i: Int, t: T) : List<T> = when(i) {
    0 -> listOf(t) + this.drop(1)
    this.lastIndex -> this.dropLast(1) + t
    else -> this.take(i) + t + this.take(this.size - i - 1)
}

fun <T> `???`(): T {
    throw RuntimeException("not implemented")
}