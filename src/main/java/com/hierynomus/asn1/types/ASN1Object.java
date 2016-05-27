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

public abstract class ASN1Object {

    protected ASN1Tag tag;

    protected ASN1Object(ASN1Tag tag) {
        this.tag = tag;
    }

    public abstract Object getValue();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ASN1Object that = (ASN1Object) o;

        if (tag != that.tag) return false;
        return getValue() != null ? getValue().equals(that.getValue()) : that.getValue() == null;

    }

    @Override
    public int hashCode() {
        int result = tag.getTag();
//        result = 31 * result + valueHash();
        return result;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "[" + getValue() + "]";
    }

    public ASN1Tag getTag() {
        return tag;
    }
}
