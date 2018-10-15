/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.security.tools.model;

import java.util.ArrayList;

/**
 * Jar - jars of a given product. Contains the classes inside of the scanned jar at a given time.
 */
public class Jar {

    private String jarName;
    private String jarHashCode;
    private ArrayList<Class> classes;

    public ArrayList<Class> getClasses() {
        return classes;
    }

    public void setClasses(ArrayList<Class> classes) {
        this.classes = classes;
    }

    public Jar(String jarName, String jarHashCode) {
        this.jarName = jarName;
        this.jarHashCode = jarHashCode;
        this.classes = new ArrayList<Class>();
    }

    public String getJarName() {
        return jarName;
    }

    public void setJarName(String jarName) {
        this.jarName = jarName;
    }

    public String getJarHashCode() {
        return jarHashCode;
    }

    public void setJarHashCode(String jarHashCode) {
        this.jarHashCode = jarHashCode;
    }
}
