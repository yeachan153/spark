/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.scheduler

import java.util.Base64

class Jwt {
  private val decoder = Base64.getUrlDecoder
  private val JWT_TOKEN_LENGTH = 3

  private def parseJWT(token: String): ujson.Value = {
    val tokenSplit = token.split("\\.")
    if (tokenSplit.length != JWT_TOKEN_LENGTH) throw new IllegalStateException("Invalid JWT")
    val payload = new String(this.decoder.decode(tokenSplit(1)))
    ujson.read(payload)
  }

  def getLongAttribute(token: String, attribute: String): Long = {
    val parsedToken = parseJWT(token)
    parsedToken.obj(attribute).num.toLong
  }
}
