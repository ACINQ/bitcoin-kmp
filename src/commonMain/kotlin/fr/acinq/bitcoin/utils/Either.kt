/*
 * Copyright 2021 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.bitcoin.utils

public sealed class Either<out L, out R> {
    public abstract val isLeft: Boolean
    public abstract val isRight: Boolean
    public abstract val left: L?
    public abstract val right: R?

    public inline fun <X> fold(fl: (L) -> X, fr: (R) -> X): X = when (this) {
        is Left -> fl(this.value)
        is Right -> fr(this.value)
    }

    public inline fun <X, Y> transform(fl: (L) -> X, fr: (R) -> Y): Either<X, Y> = when (this) {
        is Left -> Left(fl(this.value))
        is Right -> Right(fr(this.value))
    }

    public inline fun <X> map(f: (R) -> X): Either<L, X> = transform({ it }, f)

    public data class Left<out L, Nothing>(val value: L) : Either<L, Nothing>() {
        override val isLeft: Boolean = true
        override val isRight: Boolean = false
        override val left: L? = value
        override val right: Nothing? = null
    }

    public data class Right<Nothing, out R>(val value: R) : Either<Nothing, R>() {
        override val isLeft: Boolean = false
        override val isRight: Boolean = true
        override val left: Nothing? = null
        override val right: R? = value
    }
}

@Suppress("UNCHECKED_CAST")
public inline fun <L, R, X> Either<L, R>.flatMap(f: (R) -> Either<L, X>): Either<L, X> = when (this) {
    is Either.Left -> this as Either<L, X>
    is Either.Right -> f(this.value)
}

public inline fun <L, R> Either<L, R>.getOrElse(onLeft: (L) -> R): R = when (this) {
    is Either.Left -> onLeft(this.value)
    is Either.Right -> this.value
}

public fun <L, R> Either<L, R>.getOrDefault(defaultValue: R): R = when (this) {
    is Either.Left -> defaultValue
    is Either.Right -> this.value
}
