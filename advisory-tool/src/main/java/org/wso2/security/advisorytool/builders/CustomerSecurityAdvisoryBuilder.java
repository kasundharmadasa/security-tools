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

import org.apache.commons.lang3.StringUtils;
import org.wso2.security.advisorytool.config.Configuration;
import org.wso2.security.advisorytool.exeption.AdvisoryToolException;
import org.wso2.security.advisorytool.model.Patch;
import org.wso2.security.advisorytool.model.Product;
import org.wso2.security.advisorytool.model.SecurityAdvisory;
import org.wso2.security.advisorytool.model.Version;
import org.wso2.security.advisorytool.utils.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.security.advisorytool.utils.Constants.CARBON_KERNEL_4_0_0;
import static org.wso2.security.advisorytool.utils.Constants.CARBON_KERNEL_4_2_0;
import static org.wso2.security.advisorytool.utils.Constants.CARBON_KERNEL_4_3_0;
import static org.wso2.security.advisorytool.utils.Constants.CARBON_KERNEL_4_4_0;

/**
 * This class builds the customer security advisory object.
 */
public class CustomerSecurityAdvisoryBuilder extends SecurityAdvisoryBuilder {

    protected SecurityAdvisory securityAdvisory = new SecurityAdvisory();

    public void buildAdvisoryDetails(SecurityAdvisory securityAdvisory) throws AdvisoryToolException{

        SecurityAdvisory securityAdvisoryDataFromPMT = null;

        try {
            this.securityAdvisory = securityAdvisory;

            //getting the advisory details from the PMT.
            securityAdvisoryDataFromPMT = Util.getAdvisoryData(securityAdvisory.getName());

            if (securityAdvisoryDataFromPMT != null) {

                if (StringUtils.isEmpty(securityAdvisory.getPublicDisclosure())) {
                    throw new AdvisoryToolException("Public Disclosure field is empty for the advisory "
                            + securityAdvisory.getName());
                }

                if (StringUtils.isEmpty(securityAdvisory.getDescription())) {
                    this.securityAdvisory.setDescription(securityAdvisoryDataFromPMT.getDescription());
                }

                if (StringUtils.isEmpty(securityAdvisory.getImpact())) {
                    this.securityAdvisory.setImpact(securityAdvisoryDataFromPMT.getImpact());
                }

                if (StringUtils.isEmpty(securityAdvisory.getOverview())) {
                    this.securityAdvisory.setOverview(securityAdvisoryDataFromPMT.getOverview());
                }

                if (StringUtils.isEmpty(securityAdvisory.getNotes())) {
                    this.securityAdvisory.setNotes(securityAdvisoryDataFromPMT.getNotes());
                }

                if (StringUtils.isEmpty(securityAdvisory.getSeverity())) {
                    this.securityAdvisory.setSeverity(securityAdvisoryDataFromPMT.getSeverity());
                }

                if (StringUtils.isEmpty(securityAdvisory.getScore())) {
                    this.securityAdvisory.setScore(securityAdvisoryDataFromPMT.getScore());
                }

                if (StringUtils.isEmpty(securityAdvisory.getSolution())) {
                    this.securityAdvisory.setSolution(securityAdvisoryDataFromPMT.getSolution());
                }

                if (StringUtils.isEmpty(securityAdvisory.getCredits())) {
                    this.securityAdvisory.setCredits(securityAdvisoryDataFromPMT.getCredits());
                }
            }

        } catch (AdvisoryToolException e) {
            throw new AdvisoryToolException("Error occurred while building the advisory details.", e);
        }
    }

    public void buildAffectedProductsList(SecurityAdvisory securityAdvisory) throws AdvisoryToolException {

        Map<String, List<Patch>> affectedProductsMap = new HashMap<>();
        List<Product> affectedProductsList = new ArrayList<>();
        List<Product> affectedWUMProductsList = new ArrayList<>();
        List<Product> affectedPatchSupportedProductsList;
        List<String> affectedPatchNames = new ArrayList<>();
        List<Patch> supportedPatchListForAdvisory = new ArrayList<>();
        boolean hasPatchSupportedProduct = false;
        String url = "";


            List<Patch> patchListForAdvisory = Util.getApplicablePatchListForAdvisory(securityAdvisory.getName());

            if (patchListForAdvisory.isEmpty()) {
                throw new AdvisoryToolException("Applicable patch list for the Security Advisory " + securityAdvisory.getName() + " is empty.");
            }

            affectedProductsMap = Util.generateAffectedProductMapFromApplicablePatches(patchListForAdvisory);
            affectedProductsList = Util.getProductObjectListFromAffectedProductMap(affectedProductsMap);
            this.securityAdvisory.setAffectedAllProducts(affectedProductsList);

            affectedPatchSupportedProductsList = Util.getPatchSupportedProductsFromAffectedProducts(affectedProductsList);
            this.securityAdvisory.setAffectedPatchProducts(affectedPatchSupportedProductsList);

            affectedWUMProductsList = Util.getWUMProductsFromAffectedProducts(affectedProductsList);
            this.securityAdvisory.setAffectedWUMProducts(affectedWUMProductsList);

            for (Product affectedPatchSupportedProduct : affectedPatchSupportedProductsList) {
                for (Version affectedPatchSupportedVersion : affectedPatchSupportedProduct.getVersionList()) {
                    for (Patch patch : affectedPatchSupportedVersion.getPatchList()) {

                        if ("4.0.0".equals(affectedPatchSupportedVersion.getPlatformVersionNumber())) {
                            url = Configuration.getInstance().getPatchZIPCustomerLocation()
                                    + CARBON_KERNEL_4_0_0 + "/Product/"
                                    + affectedPatchSupportedProduct.getCodeName() + " "
                                    + affectedPatchSupportedVersion.getVersionNumber()
                                    + "/" + patch.getName().replace(" ", "") + ".zip";
                        }

                        if ("4.2.0".equals(affectedPatchSupportedVersion.getPlatformVersionNumber())) {
                            url = Configuration.getInstance().getPatchZIPCustomerLocation()
                                    + CARBON_KERNEL_4_2_0 + "/Product/"
                                    + affectedPatchSupportedProduct.getCodeName() + " "
                                    + affectedPatchSupportedVersion.getVersionNumber()
                                    + "/" + patch.getName().replace(" ", "") + ".zip";
                        }

                        if ("4.3.0".equals(affectedPatchSupportedVersion.getPlatformVersionNumber())) {
                            url = Configuration.getInstance().getPatchZIPCustomerLocation()
                                    + CARBON_KERNEL_4_3_0 + "/Product/"
                                    + affectedPatchSupportedProduct.getCodeName() + " "
                                    + affectedPatchSupportedVersion.getVersionNumber()
                                    + "/" + patch.getName().replace(" ", "") + ".zip";
                        }

                        if ("4.4.0".equals(affectedPatchSupportedVersion.getPlatformVersionNumber())) {
                            url = Configuration.getInstance().getPatchZIPCustomerLocation()
                                    + CARBON_KERNEL_4_4_0 + "/Product/"
                                    + affectedPatchSupportedProduct.getCodeName() + " "
                                    + affectedPatchSupportedVersion.getVersionNumber()
                                    + "/" + patch.getName().replace(" ", "") + ".zip";
                        }

                        patch.setZipLocation(url);

                        if (!affectedPatchNames.contains(patch.getName())) {
                            affectedPatchNames.add(patch.getName());
                            supportedPatchListForAdvisory.add(patch);
                        }
                    }
                }
            }
            this.securityAdvisory.setApplicablePatchList(supportedPatchListForAdvisory);
    }


    public SecurityAdvisory getSecurityAdvisory() {
        return securityAdvisory;
    }

}
