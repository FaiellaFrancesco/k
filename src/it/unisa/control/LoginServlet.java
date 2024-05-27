package it.unisa.control;

import it.unisa.model.*;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("un");
        String password = request.getParameter("pw");
        String checkout = request.getParameter("checkout");
        
        UserDao userDao = new UserDao();
        
        try {
            UserBean user = userDao.doRetrieve(username);
            
            if (user != null) {
                // Crittografa la password fornita dall'utente
                String hashedPassword = hashPassword(password);
                
                // Confronta la password crittografata con quella memorizzata nel database
                if (hashedPassword != null && hashedPassword.equals(user.getPassword())) {
                    HttpSession session = request.getSession(true);
                    session.setAttribute("currentSessionUser", user);
                    
                    if (checkout != null) {
                        response.sendRedirect(request.getContextPath() + "/account?page=Checkout.jsp");
                    } else {
                        response.sendRedirect(request.getContextPath() + "/Home.jsp");
                    }
                    return;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // Se l'autenticazione fallisce, reindirizza alla pagina di login con un messaggio di errore
        response.sendRedirect(request.getContextPath() + "/Login.jsp?action=error");
    }
    
    // Metodo per crittografare la password utilizzando SHA-256
    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
