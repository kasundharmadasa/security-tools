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

package org.wso2.security.tools.sgs.webapp.controller;

import org.apache.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.wso2.security.tools.sgs.webapp.config.ScanManagerConfiguration;
import org.wso2.security.tools.sgs.webapp.config.StartUpInit;
import org.wso2.security.tools.sgs.webapp.entity.Scanner;
import org.wso2.security.tools.sgs.webapp.service.ScanService;
import org.wso2.security.tools.sgs.webapp.wrapper.ScanListWrapper;

/**
 * Controller methods to resolve views
 */
@Controller
@RequestMapping("scanManager")
public class ScanController {

    private final ScanService scanService;

    @Autowired
    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @GetMapping(value = "/")
    public String scanManager() {
        return "scanManager/index";
    }

    @PostMapping(value = "/startScan")
    public String startScan(MultipartHttpServletRequest multipartHttpServletRequest, ModelMap map) {

        int status = scanService.startScan(multipartHttpServletRequest
                .getMultiFileMap(), multipartHttpServletRequest.getParameterMap());
        if (status == HttpStatus.SC_OK) {
            map.addAttribute("message", "Success");
            return "redirect:scans";
        } else {
            map.addAttribute("message", "An error occurred while initiating the scan.");
            return "scanManager/errorPage";
        }
    }

    @GetMapping(value = "/scanners")
    public String getScanners(@ModelAttribute("scannerConfig") ScanManagerConfiguration scannerConfiguration) {

        scannerConfiguration.setStaticScanners(StartUpInit.scanManagerConfiguration.getStaticScanners());
        scannerConfiguration.setDynamicScanners(StartUpInit.scanManagerConfiguration.getDynamicScanners());
        scannerConfiguration.setDependencyScanners(StartUpInit.scanManagerConfiguration.getDependencyScanners());
        return "scanManager/scanners";
    }

    @GetMapping(value = "/scans")
    public String getScans(@ModelAttribute("scanList") ScanListWrapper scanListWrapper) {

        scanListWrapper.setScans(scanService.getScans());
        return "scanManager/scans";
    }

    @PostMapping(value = "/stop")
    public String stopScan(@RequestParam String id, ModelMap map) {

        ResponseEntity<String> responseEntity = scanService.stopScan(id);
        if (responseEntity != null && responseEntity.getStatusCode().is2xxSuccessful()) {
            map.addAttribute("message", "Success");
            return "redirect:scans";
        } else {
            map.addAttribute("message", "Unable to stop the scan");
            return "scanManager/errorPage";
        }
    }

    @PostMapping(value = "/scanConfiguration")
    public String upload(@ModelAttribute("scannerData") Scanner selectedScanner,
                         @RequestParam String scannerID) {

        Scanner scanner = scanService.getScanner(scannerID);
        selectedScanner.setId(scanner.getId());
        selectedScanner.setName(scanner.getName());
        selectedScanner.setFields(scanner.getFields());
        return "scanManager/scanConfiguration";
    }
}
