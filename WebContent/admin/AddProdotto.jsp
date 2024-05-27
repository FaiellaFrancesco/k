<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>

<%!
    public String sanitize(String input) {
        // Utilizza un'espressione regolare per vietare caratteri speciali
        if (input != null) {
            input = input.replaceAll("[^a-zA-Z0-9]", "");
        }
        return input;
    }
%>

<!DOCTYPE html>
<html>
<head>
    <meta charset="ISO-8859-1">
    <link href="${pageContext.request.contextPath}/css/style.css" rel="stylesheet" type="text/css">
    <title>Aggiungi prodotto</title>
</head>
<body>
    <%@ include file="../fragments/header.jsp" %>
    <%@ include file="../fragments/menu.jsp" %>
    <div id="main" class="clear">
        <h2>AGGIUNGI PRODOTTO</h2>
        <form action="../catalogo" method="post" id="myform">
            <input type="hidden" name="action" value="add">
            <input type="hidden" name="page" value="admin/GestioneCatalogo.jsp"><br><br>
            <div class="tableRow">
                <p>Nome:</p>
                <p><input type="text" name="nome" value="<%= sanitize(request.getParameter("nome")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Descrizione:</p>
                <p><input type="text" name="descrizione" value="<%= sanitize(request.getParameter("descrizione")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Iva:</p>
                <p><input type="text" name="iva" value="<%= sanitize(request.getParameter("iva")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Prezzo:</p>
                <p><input type="text" name="prezzo" value="<%= sanitize(request.getParameter("prezzo")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Data:</p>
                <p><input type="text" name="dataUscita" value="<%= sanitize(request.getParameter("dataUscita")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Quantità:</p>
                <p><input type="number" name="quantità" value="<%= sanitize(request.getParameter("quantità")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Immagine:</p>
                <p><input type="text" name="img" value="<%= sanitize(request.getParameter("img")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Piattaforma:</p>
                <p><input type="text" name="piattaforma" value="<%= sanitize(request.getParameter("piattaforma")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Genere:</p>
                <p><input type="text" name="genere" value="<%= sanitize(request.getParameter("genere")) %>" required></p>
            </div>
            <div class="tableRow">
                <p>Descrizione dettagliata:</p>
                <p><input type="text" name="descDett" value="<%= sanitize(request.getParameter("descDett")) %>"></p>
            </div>
            <div class="tableRow">
                <p></p>
                <p><input type="submit" value="aggiungi"></p>
            </div>
        </form>
    </div>
    <%@ include file="../fragments/footer.jsp" %>
</body>
</html>
