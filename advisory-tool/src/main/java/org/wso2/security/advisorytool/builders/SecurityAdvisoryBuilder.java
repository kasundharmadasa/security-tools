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

import org.wso2.security.advisorytool.exeption.AdvisoryToolException;
import org.wso2.security.advisorytool.model.SecurityAdvisory;

public abstract class SecurityAdvisoryBuilder {

    public abstract void buildAdvisoryDetails(SecurityAdvisory securityAdvisory) throws AdvisoryToolException;
    public abstract void buildAffectedProductsList(SecurityAdvisory securityAdvisory) throws AdvisoryToolException;
    public abstract SecurityAdvisory getSecurityAdvisory();
}
