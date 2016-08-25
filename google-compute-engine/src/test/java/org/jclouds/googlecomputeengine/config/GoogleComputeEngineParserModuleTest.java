/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jclouds.googlecomputeengine.config;

import static org.testng.Assert.assertEquals;

import org.jclouds.googlecomputeengine.domain.Firewall;
import org.jclouds.googlecomputeengine.options.FirewallOptions;
import org.jclouds.json.Json;
import org.jclouds.json.config.GsonModule;
import org.testng.annotations.Test;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;

public class GoogleComputeEngineParserModuleTest {

   private final Json json = Guice.createInjector(new GsonModule(), new GoogleComputeEngineParserModule())
           .getInstance(Json.class);

   @Test
   public void testJson() {
      String json = this.json.toJson(
              new FirewallOptions()
                      .addAllowedRule(Firewall.Rule.create("tcp", ImmutableList.of("22")))
              .addAllowedRule(Firewall.Rule.create("udp", ImmutableList.<String>of("22")))
      ) ;


      assertEquals(json, "{\"allowed\":[{\"IPProtocol\":\"tcp\",\"ports\":[\"22\"]},{\"IPProtocol\":\"udp\",\"ports\":[\"22\"]}]}");
   }
}