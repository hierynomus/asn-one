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

import java.io.InputStream;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1Set;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.*;
import com.hierynomus.asn1.types.string.ASN1BitString;
import com.hierynomus.asn1.types.string.ASN1OctetString;

public interface ASN1Decoder {

    ASN1Tag<?> readTag(InputStream is);

    int readLength(InputStream is);

    byte[] readValue(int length, InputStream is);

    ASN1Parser<ASN1Boolean> newBooleanParser();
    ASN1Parser<ASN1Enumerated> newEnumeratedParser();
    ASN1Parser<ASN1Integer> newIntegerParser();
    ASN1Parser<ASN1Null> newNullParser();

    ASN1Parser<ASN1ObjectIdentifier> newObjectIdentifierParser();

    ASN1Parser<ASN1Sequence> newSequenceParser();

    ASN1Parser<ASN1Set> newSetParser();

    ASN1Parser<ASN1TaggedObject> newTaggedObjectParser();

    ASN1Parser<ASN1BitString> newBitStringParser();

    ASN1Parser<ASN1OctetString> newOctetStringParser();
}
