<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <%@ include file="../fragments/header.html" %>
</head>
<body>
<%@include file="../fragments/navBar.jsp" %>
<div class="container">
    <div class="row">
        <div class="page-header">
            <h1>Scan Configuration</h1>
        </div>
        <div class="col-lg-6 col-md-12 col-sm-12">
            <div class="jumbotron"
                 style="padding-top: 10px; padding-bottom: 15px; padding-left: 20px">
                <form action="/scanManager/startScan" method="post"
                      enctype="multipart/form-data">

                    <div class="form-group">
                        <label for="scanName">Scan Name</label>
                        <input type="text" class="form-control" id="scanName" name="scanName"
                               placeholder="Please enter a name to scan" required>
                    </div>
                    <br>

                    <div class="form-group">
                        <label for="scanName">Product Name</label>
                        <input type="text" class="form-control" id="productName" name="productName"
                               placeholder="Please enter the product name" required>
                    </div>
                    <br>

                    <c:if test="${scannerData.fields.size() > 0}">
                    <div class="form-group">

                        <c:forEach begin="0" end="${scannerData.fields.size()-1}"
                                   var="index">
                            <label for="${scannerData.fields.get(index).id}">${scannerData.fields
                            .get(index).displayName}</label>
                            <input type="${scannerData.fields.get(index).type}" class="form-control"
                                   id="${scannerData.fields.get(index).id}"
                                   name="${scannerData.fields.get(index).id}" required>
                            <br>
                        </c:forEach>
                        </span>
                    </div>
                    </c:if>
            </div>
            <a class="btn btn-outline-primary" href="/scanManager/scanners" role="button">Back</a>

            <button class="btn btn-primary">Start Scan</button>
            </form>
        </div>
    </div>
</div>
<%@include file="../fragments/footer.jsp" %>
</body>
</html>
