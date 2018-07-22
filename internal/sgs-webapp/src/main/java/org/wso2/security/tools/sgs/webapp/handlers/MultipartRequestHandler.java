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

package org.wso2.security.tools.sgs.webapp.handlers;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility methods for handling HTTP multipart requests
 */
public class MultipartRequestHandler {

    private static final String LINE_FEED = "\r\n";
    private String boundary;
    private HttpURLConnection httpURLConnection;
    private String charset;
    private OutputStream outputStream;
    private PrintWriter writer;

    /**
     * This constructor initializes a new HTTP POST request with content type is set to
     * multipart/form-data
     *
     * @param requestURL  Requester URL
     * @param charset     Charset
     * @param accessToken Access token to be set when sending requests through API Manager
     * @throws IOException If an I/O error occurs
     */
    public MultipartRequestHandler(String requestURL, String charset, String accessToken)
            throws IOException {

        this.charset = charset;

        // creates a unique boundary based on time stamp
        boundary = "===" + System.currentTimeMillis() + "===";
        URL url = new URL(requestURL);
        httpURLConnection = (HttpURLConnection) url.openConnection();
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setDoOutput(true); // indicates POST method
        httpURLConnection.setDoInput(true);
        httpURLConnection.setRequestProperty("Content-Type", "multipart/form-data; " +
                "boundary=" + boundary);
        httpURLConnection.setRequestProperty("Authorization", "Bearer " + accessToken);
        outputStream = httpURLConnection.getOutputStream();
        writer = new PrintWriter(new OutputStreamWriter(outputStream, charset), true);
    }

    /**
     * This constructor initializes a new HTTP POST request with content type is set to
     * multipart/form-data without the authorization header
     *
     * @param requestURL Requester URL
     * @param charset    Charset
     * @throws IOException If an I/O error occurs
     */
    public MultipartRequestHandler(String requestURL, String charset) throws IOException {

        this.charset = charset;

        // creates a unique boundary based on time stamp
        boundary = "===" + System.currentTimeMillis() + "===";
        URL url = new URL(requestURL);
        httpURLConnection = (HttpURLConnection) url.openConnection();
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setDoOutput(true); // indicates POST method
        httpURLConnection.setDoInput(true);
        httpURLConnection.setRequestProperty("Content-Type", "multipart/form-data; " +
                "boundary=" + boundary);
        outputStream = httpURLConnection.getOutputStream();
        writer = new PrintWriter(new OutputStreamWriter(outputStream, charset), true);
    }

    /**
     * Adds a form field to the request
     *
     * @param name  Field name
     * @param value Field value
     */
    public void addFormField(String name, String value) {
        writer.append("--").append(boundary).append(LINE_FEED);
        writer.append("Content-Disposition: form-data; name=\"")
                .append(name).append("\"")
                .append(LINE_FEED);
        writer.append("Content-Type: text/plain; charset=").append(charset).append(LINE_FEED);
        writer.append(LINE_FEED);
        writer.append(value).append(LINE_FEED);
        writer.flush();
    }

    /**
     * Adds a upload file section to the request
     *
     * @param fieldName  Field name
     * @param uploadFile A File to be uploaded
     * @param fileName   Name of the file
     * @throws IOException If an I/O error occurs
     */
    public void addFilePart(String fieldName, InputStream uploadFile, String fileName)
            throws IOException {
        writer.append("--").append(boundary).append(LINE_FEED);
        writer.append("Content-Disposition: form-data; name=\"").append(fieldName).append("\"; " +
                "filename=\"").append(fileName).append("\"").append(LINE_FEED);
        writer.append("Content-Type: ")
                .append(URLConnection.guessContentTypeFromName(fileName))
                .append(LINE_FEED);
        writer.append("Content-Transfer-Encoding: binary").append(LINE_FEED);
        writer.append(LINE_FEED);
        writer.flush();
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = uploadFile.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        outputStream.flush();
        uploadFile.close();
        writer.append(LINE_FEED);
        writer.flush();
    }

    /**
     * Adds a header field to the request.
     *
     * @param name  Name of the header field
     * @param value Value of the header field
     */
    public void addHeaderField(String name, String value) {
        writer.append(name).append(": ").append(value).append(LINE_FEED);
        writer.flush();
    }

    /**
     * Completes the request and receives response from the server.
     *
     * @throws IOException If an I/O error occurs
     */
    public int finish() {
        List<String> response = new ArrayList<>();
        int status = -1;

        try {
            writer.append(LINE_FEED).flush();
            writer.append("--").append(boundary).append("--").append(LINE_FEED);
            writer.close();
            // checks server's status code first
            status = httpURLConnection.getResponseCode();
            if (status == HttpsURLConnection.HTTP_OK) {
                BufferedReader reader =
                        new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
                String line = null;
                while ((line = reader.readLine()) != null) {
                    response.add(line);
                }
                reader.close();
                httpURLConnection.disconnect();
            }
        } catch (IOException e) {
            //ignored
        }
        return status;
    }

    /**
     * Get message from the response
     *
     * @return The response message
     * @throws IOException If an I/O error occurs
     */
    public String getResponseMessage() throws IOException {
        return httpURLConnection.getResponseMessage();
    }
}
