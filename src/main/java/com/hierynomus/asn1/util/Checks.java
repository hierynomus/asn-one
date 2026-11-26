/*
 *    Copyright 2016 Jeroen van Erp <jeroen@hierynomus.com>
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package com.hierynomus.asn1.util;

import com.hierynomus.asn1.ASN1ParseException;

public class Checks {

    private Checks() {
        // Do not instantiate
    }

    public static void checkState(boolean state, String messageFormat, Object... args) {
        if (!state) {
            throw new IllegalStateException(String.format(messageFormat, args));
        }
    }
    /**
     * Checks a property of the input that is being parsed.
     *
     * @throws ASN1ParseException with the formatted message if the condition does not hold
     */
    public static void checkFormat(boolean condition, String messageFormat, Object... args) {
        if (!condition) {
            throw new ASN1ParseException(messageFormat, args);
        }
    }

    public static void checkArgument(boolean bool, String messageFormat, Object... args) {
        if (!bool) {
            throw new IllegalArgumentException(String.format(messageFormat, args));
        }
    }
}
