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
package com.hierynomus.asn1.types.string;

import com.hierynomus.asn1.types.ASN1Constructed;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Primitive;
import com.hierynomus.asn1.types.ASN1Tag;

import java.util.Iterator;

/**
 * An ASN.1 STRING type can either be expressed as a Primitive encoded or Constructed encoded sequence.
 */
public abstract class ASN1String extends ASN1Object implements ASN1Primitive, ASN1Constructed {
    protected byte[] valueBytes;

    public ASN1String(ASN1Tag<?> tag, byte[] bytes) {
        super(tag);
        this.valueBytes = bytes;
    }

    @Override
    public Iterator<ASN1Object> iterator() {
        // TODO Check Constructed
        return ASN1Tag.SEQUENCE.newParser().parse(valueBytes).iterator();
    }

    public abstract int length();
}
