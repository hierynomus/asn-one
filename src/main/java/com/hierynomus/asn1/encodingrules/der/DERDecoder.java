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
package com.hierynomus.asn1.encodingrules.der;

import com.hierynomus.asn1.encodingrules.ber.BERDecoder;

public class DERDecoder extends BERDecoder {

    public DERDecoder() {
        super(false);
    }

    protected DERDecoder(boolean lenient) {
        super(lenient);
    }

    /**
     * @return a decoder that keeps objects with an unknown UNIVERSAL tag as an
     * {@link com.hierynomus.asn1.types.ASN1UnknownObject} instead of failing
     */
    public static DERDecoder lenient() {
        return new DERDecoder(true);
    }
}
