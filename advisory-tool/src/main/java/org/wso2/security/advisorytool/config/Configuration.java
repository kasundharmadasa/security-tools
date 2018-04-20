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

package org.wso2.security.advisorytool.config;

/**
 * Created by kasun on 2/27/18.
 */
public class Configuration {

    private String patchListAPI;
    private String patchDetailsAPI;
    private String advisoryDetailsAPI;

    private  String patchListAPIToken;
    private  String patchDetailsAPIToken;
    private  String advisoryDetailsAPIToken;

    private String patchZIPCustomerLocation;
    private String patchZIPPublicLocation;

    private int patchSupportPeriod;

    private Configuration() {
    }

    private static volatile Configuration instance;

    public static Configuration getInstance(){
        if(instance == null){
            synchronized (Configuration.class) {
                if(instance == null) {
                    instance = new Configuration();
                }
            }
        }
        return instance;
    }

    public String getPatchListAPI() {
        return patchListAPI;
    }

    public void setPatchListAPI(String patchListAPI) {
        this.patchListAPI = patchListAPI;
    }

    public String getPatchDetailsAPI() {
        return patchDetailsAPI;
    }

    public void setPatchDetailsAPI(String patchDetailsAPI) {
        this.patchDetailsAPI = patchDetailsAPI;
    }

    public String getPatchZIPCustomerLocation() {
        return patchZIPCustomerLocation;
    }

    public void setPatchZIPCustomerLocation(String patchZIPCustomerLocation) {
        this.patchZIPCustomerLocation = patchZIPCustomerLocation;
    }

    public String getPatchZIPPublicLocation() {
        return patchZIPPublicLocation;
    }

    public void setPatchZIPPublicLocation(String patchZIPPublicLocation) {
        this.patchZIPPublicLocation = patchZIPPublicLocation;
    }

    public String getAdvisoryDetailsAPI() {
        return advisoryDetailsAPI;
    }

    public void setAdvisoryDetailsAPI(String advisoryDetailsAPI) {
        this.advisoryDetailsAPI = advisoryDetailsAPI;
    }

    public String getPatchListAPIToken() {
        return patchListAPIToken;
    }

    public void setPatchListAPIToken(String patchListAPIToken) {
        this.patchListAPIToken = patchListAPIToken;
    }

    public String getPatchDetailsAPIToken() {
        return patchDetailsAPIToken;
    }

    public void setPatchDetailsAPIToken(String patchDetailsAPIToken) {
        this.patchDetailsAPIToken = patchDetailsAPIToken;
    }

    public String getAdvisoryDetailsAPIToken() {
        return advisoryDetailsAPIToken;
    }

    public void setAdvisoryDetailsAPIToken(String advisoryDetailsAPIToken) {
        this.advisoryDetailsAPIToken = advisoryDetailsAPIToken;
    }

    public int getPatchSupportPeriod() {
        return patchSupportPeriod;
    }

    public void setPatchSupportPeriod(int patchSupportPeriod) {
        this.patchSupportPeriod = patchSupportPeriod;
    }

}
