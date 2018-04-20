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

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.wso2.security.advisorytool.builders.CustomerSecurityAdvisoryBuilder;
import org.wso2.security.advisorytool.builders.SecurityAdvisoryBuilder;
import org.wso2.security.advisorytool.builders.SecurityAdvisoryDirector;
import org.wso2.security.advisorytool.data.SecurityAdvisoryDataHolder;
import org.wso2.security.advisorytool.exeption.AdvisoryToolException;
import org.wso2.security.advisorytool.model.SecurityAdvisory;
import org.wso2.security.advisorytool.model.SecurityAdvisoryData;
import org.wso2.security.advisorytool.utils.Constants;
import org.wso2.security.advisorytool.utils.Util;

import java.util.Scanner;

import static org.wso2.security.advisorytool.utils.Constants.LOG4J_PROPERTIES_FILE_PATH;


public class App {

    private static final Logger logger = Logger.getLogger(App.class);

    private static Integer securityAdvisoryType = 0;
    private static Integer securityAdvisoryFlow = 0;

    public static void main(String[] args) {

        try {
            PropertyConfigurator.configure(LOG4J_PROPERTIES_FILE_PATH);
            initialize();
            Util.readConfigurationsFromPropertiesFile();
            Util.loadReleasedProducts(Constants.RELEASED_PRODUCTS_FILE_PATH);
            Util.loadSecurityAdvisoryListFromFile();

            SecurityAdvisoryDirector securityAdvisoryDirector = new SecurityAdvisoryDirector();
            SecurityAdvisoryBuilder builder = null;
            SecurityAdvisoryOutputGenerator securityAdvisoryOutputGenerator = null;

            if (securityAdvisoryType == 1) {
                builder = new CustomerSecurityAdvisoryBuilder();
            }

            if (securityAdvisoryFlow == 1) {
                securityAdvisoryOutputGenerator = new SecurityAdvisoryPDFOutputGenerator();
            } else if (securityAdvisoryFlow == 2) {
                securityAdvisoryOutputGenerator = new SecurityAdvisoryXMLOutputGenerator();
            } else if (securityAdvisoryFlow == 3) {
                securityAdvisoryOutputGenerator = new SecurityAdvisoryPDFOutputGeneratorFromXML();
            } else {
                throw new AdvisoryToolException("Invalid Security Advisory flow");
            }

            SecurityAdvisoryData securityAdvisoryData = SecurityAdvisoryDataHolder.getInstance()
                    .getSecurityAdvisoryData();

            for (SecurityAdvisory securityAdvisory : securityAdvisoryData.getAdvisories()) {
                if (!(securityAdvisoryOutputGenerator instanceof SecurityAdvisoryPDFOutputGeneratorFromXML)) {
                    securityAdvisory = securityAdvisoryDirector
                            .createSecurityAdvisory(builder, securityAdvisory);
                }
                securityAdvisoryOutputGenerator.generate(securityAdvisory,
                        Constants.SECURITY_ADVISORY_OUTPUT_DIRECTORY);
            }
        } catch (AdvisoryToolException e) {
            logger.error("Error occurred while generating the security advisories",e);
        }
    }

    private static void initialize() throws AdvisoryToolException {

        try (Scanner scanner = new Scanner(System.in)) {

            System.out.println("----------Security Advisory Generator----------\n");

            System.out.println("Security Advisory Types\n");
            System.out.println("[1] Customer Security Advisory");
            System.out.println("[2] Public Security Advisory\n");
            System.out.print("Enter the desired security advisory type (1 or 2):");

            if (scanner.hasNextLine()) {
                String number = scanner.nextLine();
                if (StringUtils.isNumeric(number)) {
                    securityAdvisoryType = Integer.parseInt(number);
                }
            }

            while (securityAdvisoryType != 1 && securityAdvisoryType != 2) {
                System.out.println("Invalid advisory type. Please enter the desired advisory type (1 or 2):");
                if (scanner.hasNextLine()) {
                    String number = scanner.nextLine();
                    if (StringUtils.isNumeric(number)) {
                        securityAdvisoryType = Integer.parseInt(number);
                    }
                }
            }

            System.out.print("\nSecurity Advisory generation flows\n");
            System.out.println("\n[1] Generate Security Advisory PDF");
            System.out.println("[2] Generate Security Advisory XML");
            System.out.println("[3] Generate Security Advisory PDF from XML\n");

            System.out.print("Enter the desired security advisory flow (1,2 or 3):");


            if (scanner.hasNextLine()) {
                String number = scanner.nextLine();
                if (StringUtils.isNumeric(number)) {
                    securityAdvisoryFlow = Integer.parseInt(number);
                }
            }

            while (securityAdvisoryFlow != 1 && securityAdvisoryFlow != 2 && securityAdvisoryFlow != 3) {
                System.out.println("Invalid advisory flow. Please enter the desired advisory flow (1,2 or 3):");
                if (scanner.hasNextLine()) {
                    String number = scanner.nextLine();
                    if (StringUtils.isNumeric(number)) {
                        securityAdvisoryFlow = Integer.parseInt(number);
                    }
                }
            }

        } catch (Exception e) {
            throw new AdvisoryToolException("Error occurred while reading the token.", e);
        }
    }
}
