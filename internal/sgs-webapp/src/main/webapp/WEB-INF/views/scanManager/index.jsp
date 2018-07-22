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
            <h1>Security Scan Portal</h1>
        </div>
        <div class="col-lg-6 col-md-12 col-sm-4">
            <div class="btn-group-vertical">
                <a class="btn btn-primary" href="/scanManager/scanners" role="button">Start a New
                    Scan</a>
                <br>
                <a class="btn btn-primary" href="/scanManager/scans" role="button">View Scans</a>
            </div>
        </div>
    </div>
</div>
<%@include file="../fragments/footer.jsp" %>
</body>
</html>
