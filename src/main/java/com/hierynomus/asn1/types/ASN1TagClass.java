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
package com.hierynomus.asn1.types;

public enum ASN1TagClass {
    UNIVERSAL(0),
    APPLICATION(0x40),
    CONTEXT_SPECIFIC(0x80),
    PRIVATE(0xc0);

    private int value;

    ASN1TagClass(int value) {
        this.value = value;
    }

    public static ASN1TagClass parseClass(byte tagByte) {
        int classValue = (tagByte & 0xc0);
        for (ASN1TagClass asn1TagClass : values()) {
            if (asn1TagClass.value == classValue) {
                return asn1TagClass;
            }
        }
        throw new IllegalStateException("Could not parse ASN.1 Tag Class (should be impossible)");
    }

    public int getValue() {
        return value;
    }
}
