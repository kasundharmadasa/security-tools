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

package org.wso2.security.advisorytool.model;

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Represents a Product Version.
 */
public class Version {

    @SerializedName("version-number")
    String versionNumber;

    @SerializedName("kernel-version-number")
    String kernelVersionNumber;

    @SerializedName("platform-version-number")
    String platformVersionNumber;

    @SerializedName("patch-list")
    List<Patch> patchList = new ArrayList<>();

    @SerializedName("is-wum-supported")
    private boolean isWumSupported;

    @SerializedName("is-patch-supported")
    private boolean isPatchSupported;

    @SerializedName("is-public-supported")
    private boolean isPublicSupported;

    @SerializedName("is-deprecated")
    private boolean isDeprecated;

    public Version() {

    }


    public Date getReleasedDate() {
        return releaseDate;
    }

    public void setReleasedDate(Date releaseDate) {
        this.releaseDate = releaseDate;
    }

    private Date releaseDate;


    public Version(String versionNumber, boolean isWumSupported, boolean isPatchSupported, boolean isPublicSupported) {
        this.versionNumber = versionNumber;
        this.isWumSupported = isWumSupported;
        this.isPatchSupported = isPatchSupported;
        this.isPublicSupported = isPublicSupported;
    }

    public boolean isPublicSupported() {
        return isPublicSupported;
    }

    public void setPublicSupported(boolean publicSupported) {
        isPublicSupported = publicSupported;
    }

    public boolean isDeprecated() {
        return isDeprecated;
    }

    public void setDeprecated(boolean deprecated) {
        isDeprecated = deprecated;
    }

    public boolean isWumSupported() {
        return isWumSupported;
    }

    public void setWumSupported(boolean wumSupported) {
        isWumSupported = wumSupported;
    }

    public boolean isPatchSupported() {
        return isPatchSupported;
    }

    public void setPatchSupported(boolean patchSupported) {
        isPatchSupported = patchSupported;
    }

    public List<Patch> getPatchList() {
        return patchList;
    }

    public void setPatchList(List <Patch> patchList) {
        this.patchList =patchList;
    }

    public void setVersionNumber(String versionNumber) {
        this.versionNumber = versionNumber;
    }

    public String getVersionNumber() {
        return versionNumber;
    }

    public String getKernelVersionNumber() {
        return kernelVersionNumber;
    }

    public void setKernalVersionNumber(String kernelVersionNumber) {
        this.kernelVersionNumber = kernelVersionNumber;
    }

    public String getPlatformVersionNumber() {
        return platformVersionNumber;
    }

    public void setPlatformVersionNumber(String platformVersionNumber) {
        this.platformVersionNumber = platformVersionNumber;
    }

}

