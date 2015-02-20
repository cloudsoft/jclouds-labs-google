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
package org.jclouds.googlecomputeengine.compute;

import static org.assertj.core.api.Assertions.assertThat;
import static org.jclouds.oauth.v2.OAuthTestUtils.setCredential;
import java.util.Properties;
import java.util.Random;
import java.util.Set;

import javax.annotation.Resource;
import javax.inject.Named;

import org.jclouds.compute.RunNodesException;
import org.jclouds.compute.domain.ExecResponse;
import org.jclouds.compute.domain.NodeMetadata;
import org.jclouds.compute.domain.Template;
import org.jclouds.compute.domain.TemplateBuilder;
import org.jclouds.compute.internal.BaseComputeServiceContextLiveTest;
import org.jclouds.compute.reference.ComputeServiceConstants;
import org.jclouds.googlecomputeengine.compute.options.GoogleComputeEngineTemplateOptions;
import org.jclouds.logging.Logger;
import org.jclouds.oauth.v2.config.CredentialType;
import org.jclouds.oauth.v2.config.OAuthProperties;
import org.jclouds.scriptbuilder.statements.login.AdminAccess;
import org.jclouds.ssh.SshClient;
import org.jclouds.sshj.config.SshjSshClientModule;
import org.testng.annotations.Test;

import com.google.common.collect.Iterables;
import com.google.inject.Module;

@Test(groups = "live", testName = "GoogleComputeEngineServiceContextLiveTest")
public class GoogleComputeEngineServiceContextLiveTest extends BaseComputeServiceContextLiveTest {

   @Override
   protected Properties setupProperties() {
      Properties props = super.setupProperties();
      if (!System.getProperty(OAuthProperties.CREDENTIAL_TYPE, "")
              .equalsIgnoreCase(CredentialType.BEARER_TOKEN_CREDENTIALS.toString())) {
         setCredential(props, provider + ".credential");
      }
      return props;
   }

   @Override
   protected Module getSshModule() {
      return new SshjSshClientModule();
   }

   @Resource
   @Named(ComputeServiceConstants.COMPUTE_LOGGER)
   protected Logger logger = Logger.NULL;

   public GoogleComputeEngineServiceContextLiveTest() {
      provider = "google-compute-engine";
   }

   @Test
   public void testLaunchClusterWithMinDisk() throws RunNodesException {
      final String group = "node" + new Random().nextLong();

      TemplateBuilder templateBuilder = view.getComputeService().templateBuilder();
      templateBuilder.imageId("https://www.googleapis.com/compute/v1/projects/jclouds-gce/global/images/canopy-sql-template");
      //templateBuilder.imageId("https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-7-wheezy-v20131014");
      templateBuilder.locationId("europe-west1-b");
      //templateBuilder.hardwareId("BASIC_A2");
      Template template = templateBuilder.build();

      // test passing custom options
      GoogleComputeEngineTemplateOptions options = template.getOptions().as(GoogleComputeEngineTemplateOptions.class);
      options.runScript(AdminAccess.standard());

      NodeMetadata node = null;
      try {
         Set<? extends NodeMetadata> nodes = view.getComputeService().createNodesInGroup(group, 1, template);
         node = Iterables.getOnlyElement(nodes);
         logger.debug("Created Node: %s", node);

         SshClient client = view.utils().sshForNode().apply(node);
         client.connect();
         ExecResponse hello = client.exec("echo hello");
         assertThat(hello.getOutput().trim()).isEqualTo("hello");
      } finally {
         if (node != null) {
            view.getComputeService().destroyNode(node.getId());
         }
      }
   }

}
