package fr.acinq.bitcoin.utils

public sealed class Try<T> {
    public abstract val isSuccess: Boolean
    public val isFailure: Boolean get() = !isSuccess
    public abstract fun get(): T
    public abstract fun getOrElse(f: () -> T): T
    public abstract fun recoverWith(f: () -> Try<T>): Try<T>
    public abstract fun <R> map(f: (T) -> R): Try<R>

    public data class Success<T>(val result: T) : Try<T>() {
        override val isSuccess: Boolean = true
        override fun get(): T = result
        override fun getOrElse(f: () -> T): T = result
        override fun recoverWith(f: () -> Try<T>): Try<T> = this
        override fun <R> map(f: (T) -> R): Try<R> = runTrying { f(result) }
    }

    public data class Failure<T>(val error: Throwable) : Try<T>() {
        override val isSuccess: Boolean = false
        override fun get(): T = throw error
        override fun getOrElse(f: () -> T): T = f()
        override fun recoverWith(f: () -> Try<T>): Try<T> = f()

        @Suppress("UNCHECKED_CAST")
        override fun <R> map(f: (T) -> R): Try<R> = this as Try<R>
    }

    public companion object {
        public operator fun <T> invoke(block: () -> T): Try<T> = runTrying(block)
    }
}

public inline fun <R> runTrying(block: () -> R): Try<R> =
    try {
        Try.Success(block())
    } catch (e: Throwable) {
        Try.Failure(e)
    }

public inline fun <T, R> T.runTrying(block: T.() -> R): Try<R> =
    try {
        Try.Success(block())
    } catch (e: Throwable) {
        Try.Failure(e)
    }
