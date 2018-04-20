/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.security.advisorytool.builders;

import org.apache.log4j.Logger;
import org.wso2.security.advisorytool.exeption.AdvisoryToolException;
import org.wso2.security.advisorytool.model.SecurityAdvisory;

/**
 * This is the director class to build the security advisory.
 */

public class SecurityAdvisoryDirector {

    private static Logger logger = Logger.getLogger(SecurityAdvisoryDirector.class);

    public SecurityAdvisory createSecurityAdvisory(SecurityAdvisoryBuilder builder,
                                                   SecurityAdvisory securityAdvisory) throws AdvisoryToolException {

        try {
            System.out.println("Creating Security Advisory " + securityAdvisory.getName());
            logger.info("Creating Security Advisory " + securityAdvisory.getName());
            builder.buildAdvisoryDetails(securityAdvisory);
            builder.buildAffectedProductsList(securityAdvisory);
            return builder.getSecurityAdvisory();
        } catch (AdvisoryToolException e) {
            throw new AdvisoryToolException("Error occurred while creating the security advisory "
                    + securityAdvisory.getName(), e);
        }
    }
}
