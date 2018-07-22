/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.security.tools.sgs.webapp.service;

import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.multipart.MultipartFile;
import org.wso2.security.tools.sgs.webapp.entity.Scan;
import org.wso2.security.tools.sgs.webapp.entity.Scanner;
import org.wso2.security.tools.sgs.webapp.handlers.HttpRequestHandler;
import org.wso2.security.tools.sgs.webapp.handlers.MultipartRequestHandler;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.security.tools.sgs.webapp.config.StartUpInit.scanManagerConfiguration;

/**
 * Service layer methods to handle general methods
 */
@Service
public class ScanService {

    private static final Logger logger = LoggerFactory.getLogger(ScanService.class);

    private static final String ID = "id";
    private static final String NAME = "name";
    private static final String OWNER = "owner";
    private static final String STATUS = "status";
    private static final String SCHEME = "http";
    private static final String CHARSET_UTF8 = "UTF-8";

    /**
     * Get Scanner details for a given scanner ID
     *
     * @param scannerID
     * @return
     */
    public Scanner getScanner(String scannerID) {

        for (Scanner scanner : scanManagerConfiguration.getStaticScanners()) {
            if (scanner.getId().equals(scannerID)) {
                return scanner;
            }
        }

        for (Scanner scanner : scanManagerConfiguration.getDynamicScanners()) {
            if (scanner.getId().equals(scannerID)) {
                return scanner;
            }
        }

        for (Scanner scanner : scanManagerConfiguration.getDependencyScanners()) {
            if (scanner.getId().equals(scannerID)) {
                return scanner;
            }
        }
        return null;
    }

    /**
     * Start a scan
     *
     * @param multipartFileMultiValueMap
     * @param parameterMap
     * @return
     */
    public int startScan(MultiValueMap<String, MultipartFile> multipartFileMultiValueMap,
                         Map<String, String[]> parameterMap) {

        int responseStatus = -1;

        try {
            URI uri = (new URIBuilder())
                    .setHost(scanManagerConfiguration.getScanManagerHost())
                    .setPort(scanManagerConfiguration.getScanManagerPort())
                    .setScheme(SCHEME).setPath(scanManagerConfiguration.getStartScanURI())
                    .build();

            MultipartRequestHandler multipartRequest = new MultipartRequestHandler(uri.toString(),
                    CHARSET_UTF8);
            for (Map.Entry<String, MultipartFile> entry : multipartFileMultiValueMap
                    .toSingleValueMap().entrySet()) {
                multipartRequest.addFilePart(entry.getKey(), entry.getValue()
                        .getInputStream(), entry.getValue().getName());
            }

            for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
                multipartRequest.addFormField(entry.getKey(), String.valueOf(entry.getValue()));
            }

            responseStatus = multipartRequest.finish();
            if (responseStatus != HttpStatus.SC_OK) {
                logger.error("Error occurred while initiating the scan. " + responseStatus + " "
                        + multipartRequest.getResponseMessage());
            }
        } catch (NumberFormatException e) {
            logger.error("Unable to retrieve the scan manager port", e);
        } catch (URISyntaxException e) {
            logger.error("Unable to build the start scan URI", e);
        } catch (IOException e) {
            logger.error("Unable to start the scan", e);
        }
        return responseStatus;
    }

    /**
     * Get the list of scans in the pool
     *
     * @return
     */
    public ArrayList<Scan> getScans() {

        MultiValueMap headerMap = new LinkedMultiValueMap();
        Map<String, Object> paramMap = new HashMap<>();
        ArrayList<Scan> scanList = new ArrayList<>();

        try {
            URI uri = (new URIBuilder())
                    .setHost(scanManagerConfiguration.getScanManagerHost())
                    .setPort(scanManagerConfiguration.getScanManagerPort())
                    .setScheme(SCHEME).setPath(scanManagerConfiguration.getScansURI())
                    .build();

            ResponseEntity<String> responseEntity = HttpRequestHandler.sendGET(uri.toString(), headerMap, paramMap);
            JSONArray responseArray = new JSONArray(responseEntity.getBody());

            for (int arrayIndex = 0; arrayIndex < responseArray.length(); arrayIndex++) {
                JSONObject jsonObject = responseArray.getJSONObject(arrayIndex);
                Scan scan = new Scan();
                scan.setId(jsonObject.get(ID).toString());
                scan.setName(jsonObject.get(NAME).toString());
                scan.setOwner(jsonObject.get(OWNER).toString());
                scan.setStatus(jsonObject.get(STATUS).toString());
                scanList.add(scan);
            }

        } catch (RestClientException | JSONException | URISyntaxException e) {
            logger.error("Unable to get the scans", e);
        }
        return scanList;
    }

    /**
     * Stop a scan
     *
     * @param id
     * @return
     */
    public ResponseEntity stopScan(String id) {

        ResponseEntity<String> responseEntity = null;
        MultiValueMap headerMap = new LinkedMultiValueMap();
        headerMap.add("Content-Type", "application/json");
        Map<String, Object> paramMap = new HashMap<>();
        paramMap.put(ID, id);

        try {
            URI uri = (new URIBuilder())
                    .setHost(scanManagerConfiguration.getScanManagerHost())
                    .setPort(scanManagerConfiguration.getScanManagerPort())
                    .setScheme(SCHEME).setPath(scanManagerConfiguration.getStopScanURI())
                    .build();

            responseEntity = HttpRequestHandler.sendPOST(uri.toString(), headerMap, paramMap);

        } catch (RestClientException | JSONException | URISyntaxException e) {
            logger.error("Unable to stop the scan " + id, e);
        }
        return responseEntity;
    }
}

