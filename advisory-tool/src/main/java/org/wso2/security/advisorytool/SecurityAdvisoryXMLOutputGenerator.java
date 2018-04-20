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

package org.wso2.security.advisorytool;

import org.apache.log4j.Logger;
import org.wso2.security.advisorytool.exeption.AdvisoryToolException;
import org.wso2.security.advisorytool.model.SecurityAdvisory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.File;

/**
 * This class generates the security advisory XML.
 */
public class SecurityAdvisoryXMLOutputGenerator implements SecurityAdvisoryOutputGenerator {

    private static final Logger logger = Logger.getLogger(SecurityAdvisoryXMLOutputGenerator.class);

    @Override
    public void generate(SecurityAdvisory securityAdvisory, String outputDirectory) throws AdvisoryToolException{

        try {
            System.out.println("Security Advisory XML generation started");
            logger.info("Security Advisory XML generation started");

            File file = new File(outputDirectory + File.separator + "xml" + File.separator + securityAdvisory.getName() + ".xml");
            JAXBContext jaxbContext = JAXBContext.newInstance(SecurityAdvisory.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            jaxbMarshaller.marshal(securityAdvisory, file);

            System.out.println("Security Advisory XML generation completed");
            logger.info("Security Advisory XML generation completed");
        } catch (JAXBException e) {
            throw new AdvisoryToolException("Failed to generate the Security Advisory XML.", e);
        }

    }
}
