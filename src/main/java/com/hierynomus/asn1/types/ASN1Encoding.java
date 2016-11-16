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

public enum ASN1Encoding {
    Primitive(0x0),
    Constructed(0x20);

    private int value;

    ASN1Encoding(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static ASN1Encoding parseEncoding(byte tagByte) {
        if ((tagByte & 0x20) == 0) {
            return Primitive;
        } else {
            return Constructed;
        }
    }
}
