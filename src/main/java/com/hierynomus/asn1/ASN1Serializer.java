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
package com.hierynomus.asn1;

import java.io.IOException;
import com.hierynomus.asn1.types.ASN1Object;

public abstract class ASN1Serializer<T extends ASN1Object> {
    protected final ASN1Encoder encoder;

    public ASN1Serializer(ASN1Encoder encoder) {
        this.encoder = encoder;
    }

    public abstract int serializedLength(T asn1Object) throws IOException;

    public abstract void serialize(T asn1Object, ASN1OutputStream stream) throws IOException;
}
