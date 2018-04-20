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

import java.io.File;

public class Constants {

    public static final String CONFIGURATION_FILE_NAME = "security-advisory-tool.properties";
    public static final String SECURITY_ADVISORY_DATA_FILE_NAME = "security-advisory-data.yaml";
    public static final String RELEASED_PRODUCTS_FILE_PATH = "conf" + File.separator + "Products.xml";
    public static final String LOG4J_PROPERTIES_FILE_PATH = "conf" + File.separator + "log4j.properties";
    public static final String SECURITY_ADVISORY_OUTPUT_DIRECTORY = "output";
    public static final String SECURITY_ADVISORY_HTML_TEMPLATE = "security_advisory_html_template";
    public static final String SECURITY_ADVISORY_HTML_TEMPLATE_DIRECTORY = File.separator + "templates";

    //Common API response objects
    public static final String NAME_OBJECT_STRING= "name";
    public static final String VALUE_OBJECT_STRING = "value";

    //Advisory Data API Response Objects
    public static final String OVERVIEW = "overview_overview";
    public static final String SEVERITY = "overview_severity";
    public static final String IMPACT = "overview_impact";
    public static final String SOLUTION = "overview_solution";
    public static final String NOTE = "overview_note";
    public static final String DESCRIPTION = "overview_description";
    public static final String CVSS_SCORE = "overview_cvssScore";
    public static final String PATCHES_OBJECT_STRING = "patches";
    public static final String PATCH_NAME_PREFIX = "WSO2-CARBON-PATCH";

    //Patch Detail API Response Objects
    public static final String APPLICABLE_PRODUCTS = "overview_products";

    //Products.xml element names

    public static final String NUMBER_TAG = "number";
    public static final String IS_WUM_SUPPORTED_TAG = "isWumSupported";
    public static final String IS_PATCH_SUPPORTED_TAG = "isPatchSupported";
    public static final String PLATFORM_VERSION_TAG = "platformVersion";
    public static final String KERNEL_VERSION_TAG = "kernelVersion";
    public static final String RELEASE_DATE_TAG = "releaseDate";
    public static final String IS_DEPRECATED_TAG = "isDeprecated";
    public static final String IS_PUBLIC_SUPPORTED_TAG = "isPublicSupported";
    public static final String VERSIONS_TAG = "versions";
    public static final String VERSION_TAG = "version";
    public static final String NAME_TAG = "name";
    public static final String CODE_NAME_TAG = "codeName";
    public static final String PRODUCT_TAG = "Product";

    public static final String CARBON_KERNEL_4_0_0 = "Carbon 4.0.0";
    public static final String CARBON_KERNEL_4_2_0 = "Carbon 4.2.0 (Turing)";
    public static final String CARBON_KERNEL_4_3_0 = "Carbon 4.3.0 (Perlis)";
    public static final String CARBON_KERNEL_4_4_0 = "Carbon 4.4.0 (Wilkes)";


}
