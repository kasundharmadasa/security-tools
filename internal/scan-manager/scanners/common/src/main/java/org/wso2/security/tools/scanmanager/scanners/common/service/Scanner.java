/*
 *  Copyright (c) 2019, WSO2 Inc., WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 *
 */

package org.wso2.security.tools.scanmanager.scanners.common.service;

import org.springframework.http.ResponseEntity;
import org.wso2.security.tools.scanmanager.common.internal.model.ScannerScanRequest;

import java.io.IOException;

/**
 * Interface for the scanner.
 */
public interface Scanner {

    /**
     * Initialise the Scanner.
     *
     * @throws IOException
     */
    public void init() throws IOException;

    /**
     * Run scan.
     *
     * @param scanRequest Object that represent the required information for tha scanner operation
     */
    public ResponseEntity startScan(ScannerScanRequest scanRequest);

    /**
     * Stop the last scan for a given application.
     *
     * @param scanRequest Object that represent the required information for tha scanner operation
     * @return whether delete scan operation success
     */
    public ResponseEntity cancelScan(ScannerScanRequest scanRequest);

}
