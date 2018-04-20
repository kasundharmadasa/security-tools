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

package org.wso2.security.advisorytool;

import com.github.jknack.handlebars.Context;
import com.github.jknack.handlebars.Handlebars;
import com.github.jknack.handlebars.Template;
import com.github.jknack.handlebars.io.ClassPathTemplateLoader;
import com.github.jknack.handlebars.io.TemplateLoader;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.lowagie.text.DocumentException;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.wso2.security.advisorytool.exeption.AdvisoryToolException;
import org.wso2.security.advisorytool.model.SecurityAdvisory;
import org.wso2.security.advisorytool.utils.Constants;
import org.xhtmlrenderer.pdf.ITextRenderer;
import org.xhtmlrenderer.resource.XMLResource;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * This class generates the security advisory PDF.
 */
public class SecurityAdvisoryPDFOutputGenerator implements SecurityAdvisoryOutputGenerator {

    private static final Logger logger = Logger.getLogger(SecurityAdvisoryPDFOutputGenerator.class);

    @Override
    public void generate(SecurityAdvisory securityAdvisory, String outputDirectory) throws AdvisoryToolException {

        TypeToken<Map<String, Object>> typeToken = new TypeToken<Map<String, Object>>() {};
        Gson gson = new Gson();

        try {
            System.out.println("Security Advisory PDF generation started");
            logger.info("Security Advisory PDF generation started");

            TemplateLoader loader = new ClassPathTemplateLoader();
            loader.setPrefix(Constants.SECURITY_ADVISORY_HTML_TEMPLATE_DIRECTORY);
            loader.setSuffix(".hbs");
            Handlebars handlebars = new Handlebars(loader);
            Template template = handlebars.compile(Constants.SECURITY_ADVISORY_HTML_TEMPLATE);

            String jsonString = gson.toJson(securityAdvisory);
            Map<String, Object> pdfInfoMap = gson.fromJson(jsonString, typeToken.getType());

            Context context = Context.newBuilder(pdfInfoMap).build();
            String htmlString = template.apply(context);

            File tempFile = new File(outputDirectory + File.separator + "pdf" + File.separator + securityAdvisory.getName() + ".pdf");
            createPDFFromHTML(htmlString, tempFile.toString());

            System.out.println("Security Advisory PDF generation completed");
            logger.info("Security Advisory PDF generation completed");
        } catch (IOException e) {
            throw new AdvisoryToolException("Failed to generate the security advisory PDF.", e);
        }
    }

    /**
     * This method is used to generate the PDF from the given html string.
     *
     * @param htmlString
     * @param tempFilePath
     */
    public static void createPDFFromHTML(String htmlString, String tempFilePath) throws AdvisoryToolException {
        ByteArrayInputStream byteArrayInputStream = null;
        try {
            byteArrayInputStream = new ByteArrayInputStream(htmlString.getBytes(StandardCharsets.UTF_8));
            Document document = XMLResource.load(byteArrayInputStream).getDocument();
            ITextRenderer renderer = new ITextRenderer();
            renderer.setDocument(document, "/");
            renderer.layout();
            try (FileOutputStream fileOutputStream = new FileOutputStream(tempFilePath)) {
                renderer.createPDF(fileOutputStream);
            } catch (DocumentException e) {
                throw new AdvisoryToolException("Failed to generate the Security Advisory PDF.", e);
            }
        } catch (IOException e) {
            throw new AdvisoryToolException("Failed to generate the Security Advisory PDF.", e);
        } finally {
            if (byteArrayInputStream != null) {
                try {
                    byteArrayInputStream.close();
                } catch (IOException ignore) {
                    //Ignored. At this point, the file is saved and the GC will remove the object later
                }
            }
        }
    }
}
