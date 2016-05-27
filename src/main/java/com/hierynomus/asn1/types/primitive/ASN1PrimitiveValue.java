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
package com.hierynomus.asn1.types.primitive;

import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Primitive;
import com.hierynomus.asn1.types.ASN1Tag;

import java.util.Arrays;

public abstract class ASN1PrimitiveValue extends ASN1Object implements ASN1Primitive {

    protected byte[] valueBytes;

    public ASN1PrimitiveValue(ASN1Tag tag) {
        super(tag);
    }

    public ASN1PrimitiveValue(ASN1Tag tag, byte[] valueBytes) {
        super(tag);
        this.valueBytes = valueBytes;
    }

    protected int valueHash() {
        return Arrays.hashCode(valueBytes);
    }

}
