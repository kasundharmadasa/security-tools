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

package org.wso2.security.advisorytool.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.log4j.Logger;
import org.apache.xerces.util.SecurityManager;
import org.joda.time.DateTime;
import org.joda.time.Period;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.security.advisorytool.config.Configuration;
import org.wso2.security.advisorytool.data.ProductDataHolder;
import org.wso2.security.advisorytool.data.SecurityAdvisoryDataHolder;
import org.wso2.security.advisorytool.exeption.AdvisoryToolException;
import org.wso2.security.advisorytool.model.Patch;
import org.wso2.security.advisorytool.model.Product;
import org.wso2.security.advisorytool.model.SecurityAdvisory;
import org.wso2.security.advisorytool.model.SecurityAdvisoryData;
import org.wso2.security.advisorytool.model.Version;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.apache.xerces.impl.Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE;
import static org.apache.xerces.impl.Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE;
import static org.apache.xerces.impl.Constants.LOAD_EXTERNAL_DTD_FEATURE;
import static org.apache.xerces.impl.Constants.SAX_FEATURE_PREFIX;
import static org.apache.xerces.impl.Constants.SECURITY_MANAGER_PROPERTY;
import static org.apache.xerces.impl.Constants.XERCES_FEATURE_PREFIX;
import static org.apache.xerces.impl.Constants.XERCES_PROPERTY_PREFIX;


/**
 * This is the utility class.
 */
public class Util {

    private Util() {
    }

    private static final Logger logger = Logger.getLogger(Util.class);

    private static final String CONFIGURATION_FILE = "conf" + File.separator + Constants.CONFIGURATION_FILE_NAME;
    private static final String SECURITY_ADVISORY_DATA_FILE = "conf" + File.separator + Constants.SECURITY_ADVISORY_DATA_FILE_NAME;

    /**
     * Read the API URLs from the patch-release-tools.properties file.
     */
    public static void readConfigurationsFromPropertiesFile() throws AdvisoryToolException {

        Properties properties = new Properties();
        String username;
        String password;

        try (InputStream inputStream = new FileInputStream(CONFIGURATION_FILE)) {
            properties.load(inputStream);

            if (!StringUtils.isEmpty(properties.getProperty("Patch.List.API"))) {
                Configuration.getInstance().setPatchListAPI(properties.getProperty("Patch.List.API"));
            } else {
                throw new AdvisoryToolException("Patch List API URL cannot be empty");
            }

            if (!StringUtils.isEmpty(properties.getProperty("Patch.Details.API"))) {
                Configuration.getInstance().setPatchDetailsAPI(properties.getProperty("Patch.Details.API"));
            } else {
                throw new AdvisoryToolException("Patch Details API URL cannot be empty");
            }

            if (!StringUtils.isEmpty(properties.getProperty("Advisory.Details.API"))) {
                Configuration.getInstance().setAdvisoryDetailsAPI(properties.getProperty("Advisory.Details.API"));
            } else {
                throw new AdvisoryToolException("Advisory Details API URL cannot be empty");
            }

            if (!StringUtils.isEmpty(properties.getProperty("Patch.Support.Period"))) {
                Configuration.getInstance().setPatchSupportPeriod(Integer.parseInt(properties.getProperty("Patch.Support.Period")));
            } else {
                throw new AdvisoryToolException("Patch Support Period cannot be empty");
            }

            if (!StringUtils.isEmpty(properties.getProperty("Patch.List.API.Username"))) {
                username = properties.getProperty("Patch.List.API.Username");
            } else {
                throw new AdvisoryToolException("Patch List API username cannot be empty");
            }

            if (!StringUtils.isEmpty(properties.getProperty("Patch.List.API.Password"))) {
                password = properties.getProperty("Patch.List.API.Password");
            } else {
                throw new AdvisoryToolException("Patch List API password cannot be empty");
            }

            byte[] encodedBytes = org.apache.commons.codec.binary.Base64.encodeBase64((username + ":" + password).getBytes());
            Configuration.getInstance().setPatchListAPIToken("Basic " + new String(encodedBytes));

            if (!StringUtils.isEmpty(properties.getProperty("Patch.Details.API.Token"))) {
                Configuration.getInstance().setPatchDetailsAPIToken("Bearer " + properties.getProperty("Patch.Details.API.Token"));
            } else {
                throw new AdvisoryToolException("Patch Details API Token cannot be empty");
            }

            if (!StringUtils.isEmpty(properties.getProperty("Advisory.Details.API.Token"))) {
                Configuration.getInstance().setAdvisoryDetailsAPIToken("Bearer " + properties.getProperty("Advisory.Details.API.Token"));
            } else {
                throw new AdvisoryToolException("Advisory Details API Token cannot be empty");
            }

            if (!StringUtils.isEmpty(properties.getProperty("Customer.Patch.Zip.Location"))) {
                Configuration.getInstance().setPatchZIPCustomerLocation(properties.getProperty("Customer.Patch.Zip.Location"));
            } else {
                throw new AdvisoryToolException("Customer patch location cannot be empty");
            }

        } catch (NumberFormatException e) {
            throw new AdvisoryToolException("Invalid Patch Support Period ", e);
        } catch (IOException e) {
            throw new AdvisoryToolException("Error occurred while reading the file " + CONFIGURATION_FILE, e);
        }
    }

    /**
     * Get the advisory data from the PMT
     *
     * @param advisoryNumber
     * @return
     */
    public static SecurityAdvisory getAdvisoryData(String advisoryNumber) throws AdvisoryToolException {

        SecurityAdvisory securityAdvisory = new SecurityAdvisory();
        StringBuilder result;

        String url = Configuration.getInstance().getAdvisoryDetailsAPI();
        try {
            url = url.concat(advisoryNumber);
            result = httpConnection(url, Configuration.getInstance().getAdvisoryDetailsAPIToken());

            if (String.valueOf(result).contains("Resource not found")) {
                throw new AdvisoryToolException("The advisory name " + advisoryNumber + " cannot be found in the PMT.");
            }

            ArrayList<String> advisoryDetails = new ArrayList<>();
            JSONArray jsonMainArr = new JSONArray(String.valueOf(result));
            JSONArray jsonArray;
            JSONObject jsonObject;
            for (int i = 0; i < jsonMainArr.length(); i++) {
                jsonObject = jsonMainArr.getJSONObject(i);
                jsonArray = jsonObject.getJSONArray("value");
                advisoryDetails.add(jsonArray.get(0).toString());
            }

            securityAdvisory.setName(advisoryNumber);

            if (getIndexOfObjectFromJsonArray(Constants.OVERVIEW, jsonMainArr) != -1) {
                securityAdvisory.setOverview(advisoryDetails.get(getIndexOfObjectFromJsonArray(Constants.OVERVIEW, jsonMainArr)));
            }

            if (getIndexOfObjectFromJsonArray(Constants.SEVERITY, jsonMainArr) != -1) {
                securityAdvisory.setSeverity(advisoryDetails.get(getIndexOfObjectFromJsonArray(Constants.SEVERITY, jsonMainArr)));
            }

            if (getIndexOfObjectFromJsonArray(Constants.DESCRIPTION, jsonMainArr) != -1) {
                securityAdvisory.setDescription(advisoryDetails.get(getIndexOfObjectFromJsonArray(Constants.DESCRIPTION, jsonMainArr)));
            }

            if (getIndexOfObjectFromJsonArray(Constants.IMPACT, jsonMainArr) != -1) {
                securityAdvisory.setImpact(advisoryDetails.get(getIndexOfObjectFromJsonArray(Constants.IMPACT, jsonMainArr)));
            }

            if (getIndexOfObjectFromJsonArray(Constants.SOLUTION, jsonMainArr) != -1) {
                securityAdvisory.setSolution(advisoryDetails.get(getIndexOfObjectFromJsonArray(Constants.SOLUTION, jsonMainArr)));
            }

            if (getIndexOfObjectFromJsonArray(Constants.NOTE, jsonMainArr) != -1) {
                securityAdvisory.setNotes(advisoryDetails.get(getIndexOfObjectFromJsonArray(Constants.NOTE, jsonMainArr)));
            }

            if (getIndexOfObjectFromJsonArray(Constants.CVSS_SCORE, jsonMainArr) != -1) {
                securityAdvisory.setScore(advisoryDetails.get(getIndexOfObjectFromJsonArray(Constants.CVSS_SCORE, jsonMainArr)));
            }

        } catch (Exception e) {
            throw new AdvisoryToolException("Error occurred while getting the advisory data from PMT", e);
        }
        return securityAdvisory;
    }

    public static int getIndexOfObjectFromJsonArray(String tag, JSONArray jsonArray) throws JSONException {
        JSONObject jo;
        for (int i = 0; i < jsonArray.length(); i++) {
            jo = jsonArray.getJSONObject(i);
            if (jo.get("name").equals(tag)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * This method retrieve related names list for a given advisory number.
     *
     * @param advisoryNumber is advisory number that want to create pdf for.
     */
    private static List<String> getPatchNamesListForAdvisory(String advisoryNumber) throws AdvisoryToolException {

        String[] patchArray;
        List<String> patchList = new ArrayList<>();
        StringBuilder result = null;

        String url = Configuration.getInstance().getPatchListAPI();
        try {
            url = url.concat(advisoryNumber);
            result = httpConnection(url, Configuration.getInstance().getPatchListAPIToken());

            JSONObject jsonOb = new JSONObject(String.valueOf(result));
            String patches = jsonOb.getString(Constants.PATCHES_OBJECT_STRING);

            if ("Couldn't find any patches in the PMT".equals(patches)) {
                throw new AdvisoryToolException("Couldn't find any patches in the PMT");
            }

            patchArray = patches.split(",");

            for (String patchName : patchArray) {
                if (patchName.startsWith(Constants.PATCH_NAME_PREFIX)) {
                    patchList.add(patchName);
                } else {
                    throw new AdvisoryToolException("Invalid Patch name " + patchName);
                }
            }

        } catch (Exception e) {
            throw new AdvisoryToolException("Error occurred while retrieving the patch list for an advisory", e);
        }

        return patchList;
    }

    /**
     * This method is used to read the security-advisory-data.yaml
     *
     * @throws AdvisoryToolException
     */
    public static void loadSecurityAdvisoryListFromFile() throws AdvisoryToolException {

        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            SecurityAdvisoryData securityAdvisoryData = mapper.readValue(
                    new File(SECURITY_ADVISORY_DATA_FILE), SecurityAdvisoryData.class);

            for (SecurityAdvisory securityAdvisory : securityAdvisoryData.getAdvisories()) {
                if (StringUtils.isEmpty(securityAdvisory.getName())) {
                    throw new AdvisoryToolException("Security Advisory name cannot be empty.");
                }

                if (StringUtils.isEmpty(securityAdvisory.getTitle())) {
                    if (StringUtils.isEmpty(securityAdvisoryData.getTitle())) {
                        throw new AdvisoryToolException("Security Advisory title cannot be empty");
                    } else {
                        securityAdvisory.setTitle(securityAdvisoryData.getTitle());
                    }
                }

                if (StringUtils.isEmpty(securityAdvisory.getThanks())) {
                    if (StringUtils.isEmpty(securityAdvisoryData.getThanks())) {
                        throw new AdvisoryToolException("Security Advisory thanks cannot be empty");
                    } else {
                        securityAdvisory.setThanks(securityAdvisoryData.getThanks());
                    }
                }

                if (StringUtils.isEmpty(securityAdvisory.getDate())) {
                    if (StringUtils.isEmpty(securityAdvisoryData.getDate())) {
                        throw new AdvisoryToolException("Security Advisory date cannot be empty");
                    } else {
                        securityAdvisory.setDate(securityAdvisoryData.getDate());
                    }
                }

                if (StringUtils.isEmpty(securityAdvisory.getDescription())) {
                    securityAdvisory.setDescription(securityAdvisoryData.getDescription());
                }

                if (StringUtils.isEmpty(securityAdvisory.getOverview())) {
                    securityAdvisory.setOverview(securityAdvisoryData.getOverview());
                }

                if (StringUtils.isEmpty(securityAdvisory.getImpact())) {
                    securityAdvisory.setImpact(securityAdvisoryData.getImpact());
                }

                if (StringUtils.isEmpty(securityAdvisory.getCredits())) {
                    securityAdvisory.setCredits(securityAdvisoryData.getCredits());
                }

                if (StringUtils.isEmpty(securityAdvisory.getSolution())) {
                    securityAdvisory.setSolution(securityAdvisoryData.getSolution());
                }

                if (StringUtils.isEmpty(securityAdvisory.getPublicDisclosure())) {
                    securityAdvisory.setPublicDisclosure(securityAdvisoryData.getPublicDisclosure());
                }

                if (StringUtils.isEmpty(securityAdvisory.getNotes())) {
                    securityAdvisory.setNotes(securityAdvisoryData.getNotes());
                }

                if (StringUtils.isEmpty(securityAdvisory.getScore())) {
                    securityAdvisory.setScore(securityAdvisoryData.getScore());
                }

                if (StringUtils.isEmpty(securityAdvisory.getSeverity())) {
                    securityAdvisory.setSeverity(securityAdvisoryData.getSeverity());
                }
            }
            SecurityAdvisoryDataHolder.getInstance().setSecurityAdvisoryData(securityAdvisoryData);

        } catch (IOException e) {
            throw new AdvisoryToolException("Error occurred while reading " + SECURITY_ADVISORY_DATA_FILE, e);
        }
    }

    /**
     * This method is used to load the product list from Products.xml
     *
     * @param filePath
     */
    public static void loadReleasedProducts(String filePath) throws AdvisoryToolException {

        ArrayList<Product> productsList = new ArrayList<>();

        try {
            DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy");
            File fXmlFile = new File(filePath);
            DocumentBuilderFactory dbFactory = getSecuredDocumentBuilder();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(fXmlFile);
            doc.getDocumentElement().normalize();

            NodeList nList = doc.getElementsByTagName(Constants.PRODUCT_TAG);

            for (int i = 0; i < nList.getLength(); i++) {

                Node node = nList.item(i);

                if (node.getNodeType() == Node.ELEMENT_NODE && Constants.PRODUCT_TAG.equals(node.getNodeName())) {

                    Element element = (Element) node;
                    Product product = new Product();
                    List<Version> versionList = new ArrayList<>();

                    if (element.getElementsByTagName(Constants.NAME_TAG).item(0).getTextContent() != null) {
                        product.setName(element.getElementsByTagName(Constants.NAME_TAG).item(0).getTextContent());
                    } else {
                        throw new AdvisoryToolException("Product name element cannot be found in the Products.xml");
                    }

                    if (element.getElementsByTagName(Constants.CODE_NAME_TAG).item(0).getTextContent() != null) {
                        product.setCodeName(element.getElementsByTagName(Constants.CODE_NAME_TAG).item(0).getTextContent());
                    } else {
                        throw new AdvisoryToolException("Product codename element cannot be found in the Products.xml");
                    }

                    NodeList versionsElementList = element.getElementsByTagName(Constants.VERSIONS_TAG).item(0).getChildNodes();

                    for (int j = 0; j < versionsElementList.getLength(); j++) {

                        if (versionsElementList.item(j).getNodeType() == Node.ELEMENT_NODE && Constants.VERSION_TAG
                                .equals(versionsElementList.item(j).getNodeName())) {

                            Element versionElement = (Element) versionsElementList.item(j);
                            Version versionObject = new Version();

                            if (versionElement.getElementsByTagName(Constants.NUMBER_TAG).item(0).getTextContent() != null) {
                                versionObject.setVersionNumber(versionElement
                                        .getElementsByTagName(Constants.NUMBER_TAG).item(0).getTextContent());
                            } else {
                                throw new AdvisoryToolException("Version number element cannot be found for " + product.getName() + " in the Products.xml");
                            }

                            if (versionElement.getElementsByTagName(Constants.PLATFORM_VERSION_TAG).item(0).getTextContent() != null) {
                                versionObject.setPlatformVersionNumber(versionElement
                                        .getElementsByTagName(Constants.PLATFORM_VERSION_TAG).item(0).getTextContent());
                            } else {
                                throw new AdvisoryToolException("<platformVersion> element cannot be found for " + product.getName() + " in the Products.xml");
                            }

                            if (versionElement.getElementsByTagName(Constants.KERNEL_VERSION_TAG).item(0).getTextContent() != null) {
                                versionObject.setKernalVersionNumber(versionElement
                                        .getElementsByTagName(Constants.KERNEL_VERSION_TAG).item(0).getTextContent());
                            } else {
                                throw new AdvisoryToolException("<kernelVersion> element cannot be found for " + product.getName() + " in the Products.xml");
                            }

                            if (versionElement.getElementsByTagName(Constants.RELEASE_DATE_TAG).item(0).getTextContent() != null) {
                                versionObject.setReleasedDate(dateFormat.parse(versionElement
                                        .getElementsByTagName(Constants.RELEASE_DATE_TAG).item(0).getTextContent()));
                            } else {
                                throw new AdvisoryToolException("<releaseDate> element cannot be found for " + product.getName() + " in the Products.xml");
                            }

                            if (versionElement.getElementsByTagName(Constants.IS_WUM_SUPPORTED_TAG).item(0) != null) {
                                versionObject.setWumSupported(Boolean.parseBoolean(versionElement
                                        .getElementsByTagName(Constants.IS_WUM_SUPPORTED_TAG).item(0).getTextContent()));
                            } else {
                                logger.warn("<" + Constants.IS_WUM_SUPPORTED_TAG + "> element cannot be found for "
                                        + product.getName() + " " + versionObject.getVersionNumber() + ". Using the default value as false.");
                                versionObject.setWumSupported(false);
                            }

                            if (versionElement.getElementsByTagName(Constants.IS_PATCH_SUPPORTED_TAG).item(0) != null) {
                                versionObject.setPatchSupported(Boolean.parseBoolean(versionElement
                                        .getElementsByTagName(Constants.IS_PATCH_SUPPORTED_TAG).item(0).getTextContent()));
                            } else {
                                logger.warn("<" + Constants.IS_PATCH_SUPPORTED_TAG + "> element cannot be found for "
                                        + product.getName() + " " + versionObject.getVersionNumber() + ". Using the default value as false.");
                                versionObject.setPatchSupported(false);
                            }

                            if (versionElement.getElementsByTagName(Constants.IS_DEPRECATED_TAG).item(0) != null) {
                                versionObject.setDeprecated(Boolean.parseBoolean(versionElement
                                        .getElementsByTagName(Constants.IS_DEPRECATED_TAG).item(0).getTextContent()));
                            } else {
                                logger.warn("<" + Constants.IS_DEPRECATED_TAG + "> element cannot be found for "
                                        + product.getName() + " " + versionObject.getVersionNumber() + ". Using the default value as false.");
                                versionObject.setDeprecated(false);
                            }

                            if (versionElement.getElementsByTagName(Constants.IS_PUBLIC_SUPPORTED_TAG).item(0) != null) {
                                versionObject.setPublicSupported(Boolean.parseBoolean(versionElement
                                        .getElementsByTagName(Constants.IS_PUBLIC_SUPPORTED_TAG).item(0).getTextContent()));
                            } else {
                                logger.warn("<" + Constants.IS_PUBLIC_SUPPORTED_TAG + "> element cannot be found for "
                                        + product.getName() + " " + versionObject.getVersionNumber() + ". Using the default value as false.");
                                versionObject.setPublicSupported(false);
                            }
                            versionList.add(versionObject);
                        }
                    }
                    product.setVersionList(versionList);
                    productsList.add(product);
                }
            }

        } catch (SAXException | IOException | ParserConfigurationException | ParseException e) {
            throw new AdvisoryToolException("SAXException occurred while parsing the file " + filePath, e);
        }

        ProductDataHolder.getInstance().setProductList(productsList);
    }

    /**
     * This method is used to get the secured document builder object.
     *
     * @return
     */
    private static DocumentBuilderFactory getSecuredDocumentBuilder() {

        int ENTITY_EXPANSION_LIMIT = 0;
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setXIncludeAware(false);
        documentBuilderFactory.setExpandEntityReferences(false);

        try {
            documentBuilderFactory.setFeature(SAX_FEATURE_PREFIX +
                    EXTERNAL_GENERAL_ENTITIES_FEATURE, false);
        } catch (ParserConfigurationException e) {
            logger.error("Failed to load XML Processor Feature " +
                    EXTERNAL_GENERAL_ENTITIES_FEATURE);
        }

        try {
            documentBuilderFactory.setFeature(SAX_FEATURE_PREFIX +
                    EXTERNAL_PARAMETER_ENTITIES_FEATURE, false);
        } catch (ParserConfigurationException e) {
            logger.error("Failed to load XML Processor Feature " +
                    EXTERNAL_PARAMETER_ENTITIES_FEATURE);
        }

        try {
            documentBuilderFactory.setFeature(XERCES_FEATURE_PREFIX +
                    LOAD_EXTERNAL_DTD_FEATURE, false);
        } catch (ParserConfigurationException e) {
            logger.error("Failed to load XML Processor Feature " +
                    LOAD_EXTERNAL_DTD_FEATURE);
        }

        SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
        documentBuilderFactory.setAttribute(XERCES_PROPERTY_PREFIX +
                SECURITY_MANAGER_PROPERTY, securityManager);

        return documentBuilderFactory;
    }

    /**
     * Get patch details from the PMT.
     *
     * @param patchName
     * @return
     */
    public static Patch getPatchDetails(String patchName) throws AdvisoryToolException {

        int jsonMainArrayIndex;
        StringBuilder result = null;
        Patch patch = new Patch();

        List<String> applicableProductAndVersionStringList = new ArrayList<>();

        try {

            String url = Configuration.getInstance().getPatchDetailsAPI();
            url = url.concat(patchName);
            result = httpConnection(url, Configuration.getInstance().getPatchDetailsAPIToken());

            if (String.valueOf(result).contains("Resource not found")) {
                throw new AdvisoryToolException("Patch " + patchName + " cannot be found in the PMT.");
            }

            JSONArray jsonMainArr = new JSONArray(String.valueOf(result));

            for (jsonMainArrayIndex = 0; jsonMainArrayIndex < jsonMainArr.length(); jsonMainArrayIndex++) {
                if (jsonMainArr.getJSONObject(jsonMainArrayIndex)
                        .getString(Constants.NAME_OBJECT_STRING).equals(Constants.APPLICABLE_PRODUCTS)) {

                    JSONObject jsonObject = jsonMainArr.getJSONObject(jsonMainArrayIndex);
                    JSONArray jsonArray = jsonObject.getJSONArray(Constants.VALUE_OBJECT_STRING);
                    for (int jsonArrayIndex = 0; jsonArrayIndex < jsonArray.length(); jsonArrayIndex++) {

                        String[] array = jsonArray.get(jsonArrayIndex).toString().split("(?=\\s\\d)");//|(?<=\d)(?=\D)
                        if (!"Carbon".equals(array[0])) {
                            //WSO2 prefix will get appended to the product names returned from the PMT
                            // as we maintain products in our Products.xml with the WSO2 prefix.
                            applicableProductAndVersionStringList.add("WSO2 ".concat(jsonArray.get(jsonArrayIndex).toString()));
                        } else {
                            logger.warn(jsonArray.get(jsonArrayIndex).toString()
                                    + " is marked as an applicable product for the patch " + patchName);
                        }
                    }
                }
            }
            patch.setName(patchName);
            patch.setApplicableProductAndVersionStrings(applicableProductAndVersionStringList);

        } catch (JSONException e) {
            throw new AdvisoryToolException("Error occurred while retrieving the patch details from PMT.", e);
        }

        return patch;
    }

    /**
     * This method is used to initiate an HTTP connection and retrieve the response.
     *
     * @param url
     * @param apiToken
     * @return
     */
    private static StringBuilder httpConnection(String url, String apiToken) throws AdvisoryToolException {

        HttpResponse response = null;
        StringBuilder result = new StringBuilder();
        String line = "";
        BufferedReader rd = null;

        try {
            HttpClient client = HttpClientBuilder.create().build();
            HttpGet request = new HttpGet(url);
            request.addHeader("Authorization", apiToken);
            response = client.execute(request);

            rd = new BufferedReader(
                    new InputStreamReader(response.getEntity().getContent()));

            while ((line = rd.readLine()) != null) {
                result.append(line);
            }

        } catch (Exception e) {
            throw new AdvisoryToolException("Failed to initialize an HTTP connection", e);
        } finally {
            if (rd != null) {
                try {
                    rd.close();
                } catch (IOException e) {
                    throw new AdvisoryToolException("Failed to close the buffered reader", e);
                }
            }
        }
        return result;
    }

    /**
     * This method is used to get the details of and affected product from the Products.xml
     *
     * @param affectedProductsMap
     * @return
     */
    public static List<Product> getProductObjectListFromAffectedProductMap(Map<String, List<Patch>> affectedProductsMap)
            throws AdvisoryToolException {

        List<Product> affectedProductList = new ArrayList<>();
        DateTime dateTime = new DateTime();
        Product affectedProductObject;
        Version affectedVersion;
        boolean isDuplicateProduct = false;
        boolean hasAMatchingProduct = false;
        List<Product> releasedProductList = ProductDataHolder.getInstance().getProductList();

        for (Map.Entry<String, List<Patch>> affectedProductMapObject : affectedProductsMap.entrySet()) {

            affectedProductObject = new Product();
            affectedVersion = new Version();
            isDuplicateProduct = false;
            hasAMatchingProduct = false;

            String key = affectedProductMapObject.getKey();
            String[] array = key.split("(?=\\s\\d)");

            for (Product releasedProduct : releasedProductList) {
                if (releasedProduct.getName().equals(array[0])) {
                    hasAMatchingProduct = true;

                    affectedProductObject.setName(releasedProduct.getName());
                    affectedProductObject.setCodeName(releasedProduct.getCodeName());

                    for (Version releasedVersion : releasedProduct.getVersionList()) {
                        if (releasedVersion.getVersionNumber().equals(array[1].replace(" ", ""))) {

                            DateTime productDate = new DateTime(releasedVersion.getReleasedDate());
                            Period period = new Period(productDate, dateTime);

                            if ((period.getYears() < Configuration.getInstance().getPatchSupportPeriod()) &&
                                    !releasedVersion.isDeprecated()) {

                                affectedVersion.setPatchList(affectedProductMapObject.getValue());
                                affectedVersion.setVersionNumber(releasedVersion.getVersionNumber());
                                affectedVersion.setPublicSupported(releasedVersion.isPublicSupported());
                                affectedVersion.setPatchSupported(releasedVersion.isPatchSupported());
                                affectedVersion.setWumSupported(releasedVersion.isWumSupported());
                                affectedVersion.setReleasedDate(releasedVersion.getReleasedDate());
                                affectedVersion.setKernalVersionNumber(releasedVersion.getKernelVersionNumber());
                                affectedVersion.setPlatformVersionNumber(releasedVersion.getPlatformVersionNumber());
                            }
                            break;
                        }
                    }
                    break;
                }
            }

            //check whether there is already a product object in the affected product list with the same name.
            for (Product affectedProductListObject : affectedProductList) {
                if (affectedProductListObject.getName().equals(array[0])) {
                    affectedProductListObject.getVersionList().add(affectedVersion);
                    affectedProductListObject.getVersionList().sort(Comparator.comparing(Version::getVersionNumber));
                    isDuplicateProduct = true;
                    break;
                }
            }

            if (hasAMatchingProduct && !isDuplicateProduct) {
                affectedProductObject.getVersionList().add(affectedVersion);
                affectedProductObject.getVersionList().sort(Comparator.comparing(Version::getVersionNumber));
                affectedProductList.add(affectedProductObject);
            }

            if (!hasAMatchingProduct) {
                throw new AdvisoryToolException("Unable to find the product " + array[0] + " in the Products.xml");
            }
        }
        affectedProductList.sort(Comparator.comparing(Product::getName));

        return affectedProductList;
    }

    public static Product getProductDetailsFromProductAndVersionString(String productAndVersionString) {

        Product product = new Product();
        Version version = new Version();
        List<Product> releasedProductList = ProductDataHolder.getInstance().getProductList();

        String[] array = productAndVersionString.split("(?=\\s\\d)");

        for (Product releasedProduct : releasedProductList) {
            if (releasedProduct.getName().equals(array[0].trim())) {

                product.setName(releasedProduct.getName());
                product.setCodeName(releasedProduct.getCodeName());
                for (Version releasedVersion : releasedProduct.getVersionList()) {

                    if (releasedVersion.getVersionNumber().equals(array[1].replace(" ", ""))) {
                        version.setVersionNumber(releasedVersion.getVersionNumber());
                        version.setPlatformVersionNumber(releasedVersion.getPlatformVersionNumber());
                        version.setKernalVersionNumber(releasedVersion.getKernelVersionNumber());
                        version.setDeprecated(releasedVersion.isDeprecated());
                        version.setPublicSupported(releasedVersion.isPublicSupported());
                        version.setPatchSupported(releasedVersion.isPatchSupported());
                        version.setWumSupported(releasedVersion.isWumSupported());
                        version.setReleasedDate(releasedVersion.getReleasedDate());

                        product.getVersionList().add(version);
                        break;
                    }
                }
                break;
            }
        }

        return product;
    }

    /**
     * This method is used to get the applicable patch information from the PMT.
     *
     * @param advisoryName
     * @return
     */
    public static List<Patch> getApplicablePatchListForAdvisory(String advisoryName) throws AdvisoryToolException {
        List<Patch> applicablePatchList = new ArrayList<>();
        List<String> patchNamesListForAdvisory;

        patchNamesListForAdvisory = getPatchNamesListForAdvisory(advisoryName);
        for (String patchName : patchNamesListForAdvisory) {
            applicablePatchList.add(getPatchDetails(patchName));
        }
        return applicablePatchList;
    }

    /**
     * This method is used to generate the affected products map from the applicable products list.
     *
     * @param applicablePatchList
     * @return
     */
    public static Map<String, List<Patch>> generateAffectedProductMapFromApplicablePatches(List<Patch> applicablePatchList)
            throws AdvisoryToolException {
        Map<String, List<Patch>> affectedProductAndVersionMap = new HashMap<>();
        List<Patch> patchList;
        Set<String> affectedProductAndVersionStringSet;

        for (Patch patch : applicablePatchList) {
            affectedProductAndVersionStringSet = new HashSet<>(patch.getApplicableProductAndVersionStrings());
            patchList = new ArrayList<>();
            patchList.add(patch);

            for (String affectedProductAndVersionString : affectedProductAndVersionStringSet) {
                if (affectedProductAndVersionMap.containsKey(affectedProductAndVersionString)) {
                    affectedProductAndVersionMap.get(affectedProductAndVersionString).add(patch);
                } else {
                    affectedProductAndVersionMap.put(affectedProductAndVersionString, patchList);
                }
            }
        }
        return affectedProductAndVersionMap;
    }

    /**
     * This method is used to extract the WUM supported products list from the affected products list.
     *
     * @param affectedProductsList
     * @return
     */
    public static List<Product> getWUMProductsFromAffectedProducts(List<Product> affectedProductsList) {

        List<Product> affectedWUMProductsList = new ArrayList<>();
        List<Version> affectedWUMVersionList = new ArrayList<>();

        for (Product affectedProduct : affectedProductsList) {
            Product affectedWUMProduct = new Product();
            for (Version affectedVersion : affectedProduct.getVersionList()) {
                if (affectedVersion.isWumSupported()) {
                    affectedWUMVersionList.add(affectedVersion);
                }
            }

            if (!affectedWUMVersionList.isEmpty()) {
                affectedWUMProduct.setName(affectedProduct.getName());
                affectedWUMProduct.setCodeName(affectedProduct.getCodeName());
                affectedWUMProduct.getVersionList().addAll(affectedWUMVersionList);
                affectedWUMProductsList.add(affectedWUMProduct);
                affectedWUMVersionList.clear();
            }

        }

        return affectedWUMProductsList;
    }

    /**
     * This method is used to extract the Patch supported products list from the affected products list.
     *
     * @param affectedProductsList
     * @return
     */
    public static List<Product> getPatchSupportedProductsFromAffectedProducts(List<Product> affectedProductsList) {

        List<Product> affectedPatchSupportedProductsList = new ArrayList<>();
        List<Version> affectedPatchSupportedVersionList = new ArrayList<>();
        Product affectedPatchSupportedProduct;

        for (Product affectedProduct : affectedProductsList) {
            affectedPatchSupportedProduct = new Product();
            for (Version affectedVersion : affectedProduct.getVersionList()) {
                if (affectedVersion.isPatchSupported()) {
                    affectedPatchSupportedVersionList.add(affectedVersion);
                }
            }

            if (!affectedPatchSupportedVersionList.isEmpty()) {
                affectedPatchSupportedProduct.setName(affectedProduct.getName());
                affectedPatchSupportedProduct.setCodeName(affectedProduct.getCodeName());
                affectedPatchSupportedProduct.getVersionList().addAll(affectedPatchSupportedVersionList);
                affectedPatchSupportedProductsList.add(affectedPatchSupportedProduct);
                affectedPatchSupportedVersionList.clear();
            }
        }

        return affectedPatchSupportedProductsList;
    }
}
