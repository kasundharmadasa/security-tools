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
 */

package org.wso2.security.tools.sgs.webapp.config;

import org.wso2.security.tools.sgs.webapp.entity.Scanner;

import java.util.List;

/**
 * Scan Manager configuration model class
 */
public class ScanManagerConfiguration {

    private String clientId;
    private String clientSecret;
    private String accessTokenUri;
    private String scanManagerHost;
    private String scanManagerPort;
    private String startScanURI;
    private String stopScanURI;
    private String scansURI;
    private List<Scanner> staticScanners;
    private List<Scanner> dynamicScanners;
    private List<Scanner> dependencyScanners;

    private ScanManagerConfiguration() {
    }

    public String getStopScanURI() {
        return stopScanURI;
    }

    public void setStopScanURI(String stopScanURI) {
        this.stopScanURI = stopScanURI;
    }

    public String getScansURI() {
        return scansURI;
    }

    public void setScansURI(String scansURI) {
        this.scansURI = scansURI;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getAccessTokenUri() {
        return accessTokenUri;
    }

    public void setAccessTokenUri(String accessTokenUri) {
        this.accessTokenUri = accessTokenUri;
    }

    public String getScanManagerHost() {
        return scanManagerHost;
    }

    public void setScanManagerHost(String scanManagerHost) {
        this.scanManagerHost = scanManagerHost;
    }

    public int getScanManagerPort() throws NumberFormatException {
        return Integer.parseInt(scanManagerPort);
    }

    public void setScanManagerPort(String scanManagerPort) {
        this.scanManagerPort = scanManagerPort;
    }

    public String getStartScanURI() {
        return startScanURI;
    }

    public void setStartScanURI(String startScanURI) {
        this.startScanURI = startScanURI;
    }

    public List<Scanner> getDynamicScanners() {
        return dynamicScanners;
    }

    public void setDynamicScanners(List<Scanner> dynamicScanners) {
        this.dynamicScanners = dynamicScanners;
    }

    public List<Scanner> getDependencyScanners() {
        return dependencyScanners;
    }

    public void setDependencyScanners(List<Scanner> dependencyScanners) {
        this.dependencyScanners = dependencyScanners;
    }

    public List<Scanner> getStaticScanners() {
        return staticScanners;
    }

    public void setStaticScanners(List<Scanner> staticScanners) {
        this.staticScanners = staticScanners;
    }
}
