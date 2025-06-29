package com.security.middleware;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import javax.servlet.ServletInputStream;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.*;
import java.util.logging.*;
import java.util.regex.Pattern;

public class SecurityMiddleware {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java -jar security-middleware.jar [config-file-path]");
            return;
        }

        String configPath = args[0];
        Properties config = loadConfiguration(configPath);

        if (config == null) {
            System.err.println("Failed to load configuration from: " + configPath);
            return;
        }

        int port = Integer.parseInt(config.getProperty("server.port", "8080"));

        try {
            Server server = new Server(port);

            ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
            context.setContextPath("/");

            SecurityServlet securityServlet = new SecurityServlet(config);
            context.addServlet(new ServletHolder(securityServlet), "/*");

            HandlerList handlers = new HandlerList();
            handlers.addHandler(context);

            server.setHandler(handlers);
            server.start();

            System.out.println("Security Middleware started on port " + port);
            System.out.println("Real backend: " + config.getProperty("backend.real.url"));
            System.out.println("Honeypot backend: " + config.getProperty("backend.honeypot.url"));

            server.join();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Properties loadConfiguration(String path) {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(path)) {
            props.load(fis);
            return props;
        } catch (IOException e) {
            System.err.println("Error loading configuration: " + e.getMessage());
            return null;
        }
    }

    private static class SecurityServlet extends HttpServlet {

        private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("(?i)(\\b(select|insert|delete|drop|update|alter|union)\\b\\s+.+)|(\\bor\\b\\s+\\d+=\\d+)|(--)|('|;)");
        private static final Pattern XSS_PATTERN = Pattern.compile("(?i).*(<script|javascript:|on\\w+\\s*=|<iframe|<img|alert\\(|eval\\(|document\\.|window\\.).*");
        private static final Pattern RCE_PATTERN = Pattern.compile("(?i).*(\\$\\{|#\\{|\\bexec\\b|\\beval\\b|\\bsystem\\b|Process\\.|Runtime\\.).*");

        private static final Logger LOGGER = Logger.getLogger(SecurityServlet.class.getName());

        private final String realBackendUrl;
        private final String honeypotBackendUrl;
        private final String dbConnectionUrl;
        private final String dbUsername;
        private final String dbPassword;
        private final boolean enableLogging;

        public SecurityServlet(Properties config) throws ServletException {
            this.realBackendUrl = config.getProperty("backend.real.url");
            this.honeypotBackendUrl = config.getProperty("backend.honeypot.url");
            this.dbConnectionUrl = config.getProperty("db.url");
            this.dbUsername = config.getProperty("db.username");
            this.dbPassword = config.getProperty("db.password");
            this.enableLogging = Boolean.parseBoolean(config.getProperty("logging.enabled", "true"));

            try {
                FileHandler fh = new FileHandler("security-middleware.log", true);
                fh.setFormatter(new SimpleFormatter());
                LOGGER.addHandler(fh);
                LOGGER.setLevel(Level.INFO);
            } catch (IOException e) {
                throw new ServletException("Failed to set up logging", e);
            }

            if (realBackendUrl == null || honeypotBackendUrl == null)
                throw new ServletException("Backend URLs not properly configured");

            if (enableLogging) {
                if (dbConnectionUrl == null || dbUsername == null || dbPassword == null)
                    throw new ServletException("Database configuration not properly set");
                try {
                    Class.forName("org.mariadb.jdbc.Driver");
                } catch (ClassNotFoundException e) {
                    throw new ServletException("MySQL JDBC Driver not found", e);
                }
            }
        }

        @Override
        protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            CachedHttpServletRequest wrappedRequest = new CachedHttpServletRequest(request);
            boolean isMalicious = containsMaliciousContent(wrappedRequest);
            String targetUrl = isMalicious ? honeypotBackendUrl : realBackendUrl;

            if (isMalicious && enableLogging) {
                logAttackToDatabase(wrappedRequest);
                LOGGER.warning("Detected attack from " + request.getRemoteAddr() + ", forwarding to honeypot");
            }

            forwardRequest(wrappedRequest, response, targetUrl);
        }

        private void forwardRequest(HttpServletRequest request, HttpServletResponse response, String targetBaseUrl) throws IOException {
            try {
                String requestUri = request.getRequestURI();
                String queryString = request.getQueryString();
                String fullTargetUrl = targetBaseUrl + requestUri + (queryString != null ? "?" + queryString : "");

                HttpURLConnection connection = (HttpURLConnection) new URL(fullTargetUrl).openConnection();
                connection.setRequestMethod(request.getMethod());

                Enumeration<String> headerNames = request.getHeaderNames();
                while (headerNames.hasMoreElements()) {
                    String name = headerNames.nextElement();
                    connection.setRequestProperty(name, request.getHeader(name));
                }

                if ("POST".equalsIgnoreCase(request.getMethod()) || "PUT".equalsIgnoreCase(request.getMethod())) {
                    connection.setDoOutput(true);
                    try (OutputStream os = connection.getOutputStream();
                         BufferedReader reader = request.getReader()) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            os.write(line.getBytes());
                        }
                    }
                }

                response.setStatus(connection.getResponseCode());
                for (Map.Entry<String, List<String>> entry : connection.getHeaderFields().entrySet()) {
                    if (entry.getKey() != null) {
                        response.setHeader(entry.getKey(), String.join(",", entry.getValue()));
                    }
                }

                try (InputStream is = connection.getResponseCode() >= 400 ? connection.getErrorStream() : connection.getInputStream();
                     OutputStream os = response.getOutputStream()) {
                    if (is != null) {
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = is.read(buffer)) != -1) {
                            os.write(buffer, 0, bytesRead);
                        }
                    }
                }
                connection.disconnect();

            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error forwarding request", e);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("Error forwarding request: " + e.getMessage());
            }
        }

        private boolean containsMaliciousContent(HttpServletRequest request) {
            for (String param : request.getParameterMap().keySet()) {
                for (String value : request.getParameterValues(param)) {
                    if (isMalicious(value)) return true;
                }
            }
            for (String header : Collections.list(request.getHeaderNames())) {
                if (!List.of("host", "connection", "accept", "content-length", "content-type").contains(header.toLowerCase())) {
                    if (isMalicious(request.getHeader(header))) return true;
                }
            }
            if ("POST".equalsIgnoreCase(request.getMethod()) || "PUT".equalsIgnoreCase(request.getMethod())) {
                try (BufferedReader reader = request.getReader()) {
                    StringBuilder body = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        body.append(line);
                    }
                    if (isMalicious(body.toString())) return true;
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Failed to read request body", e);
                }
            }
            return false;
        }

        private boolean isMalicious(String input) {
            if (input == null) return false;
            return SQL_INJECTION_PATTERN.matcher(input).find() ||
                   XSS_PATTERN.matcher(input).find() ||
                   RCE_PATTERN.matcher(input).find();
        }

        private void logAttackToDatabase(HttpServletRequest request) {
            String remoteAddr = request.getRemoteAddr();
            String requestURI = request.getRequestURI();
            String method = request.getMethod();
            String queryString = Optional.ofNullable(request.getQueryString()).orElse("");
            String userAgent = Optional.ofNullable(request.getHeader("User-Agent")).orElse("");
            Date timestamp = new Date();

            StringBuilder parameters = new StringBuilder();
            for (String param : request.getParameterMap().keySet()) {
                for (String value : request.getParameterValues(param)) {
                    parameters.append(param).append("=").append(value).append("; ");
                }
            }

            String requestBody = "";
            if (("POST".equals(method) || "PUT".equals(method)) && request instanceof CachedHttpServletRequest) {
                requestBody = ((CachedHttpServletRequest) request).getBody();
            }

            try (Connection conn = DriverManager.getConnection(dbConnectionUrl, dbUsername, dbPassword);
                 PreparedStatement stmt = conn.prepareStatement(
                         "INSERT INTO security_logs (ip_address, request_uri, method, query_string, parameters, request_body, user_agent, timestamp, attack_type) " +
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            ) {
                stmt.setString(1, remoteAddr);
                stmt.setString(2, requestURI);
                stmt.setString(3, method);
                stmt.setString(4, queryString);
                stmt.setString(5, parameters.toString());
                stmt.setString(6, requestBody);
                stmt.setString(7, userAgent);
                stmt.setTimestamp(8, new java.sql.Timestamp(timestamp.getTime()));

                String combined = requestURI + parameters + requestBody;
                String attackType = "Unknown";
                if (SQL_INJECTION_PATTERN.matcher(combined).find()) attackType = "SQL Injection";
                else if (XSS_PATTERN.matcher(combined).find()) attackType = "XSS";
                else if (RCE_PATTERN.matcher(combined).find()) attackType = "RCE";

                stmt.setString(9, attackType);
                stmt.executeUpdate();
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Failed to log attack to database", e);
            }
        }
    }

    private static class CachedHttpServletRequest extends HttpServletRequestWrapper {
        private final String body;

        public CachedHttpServletRequest(HttpServletRequest request) throws IOException {
            super(request);
            StringBuilder stringBuilder = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    stringBuilder.append(line);
                }
            }
            this.body = stringBuilder.toString();
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream bais = new ByteArrayInputStream(body.getBytes());
            return new ServletInputStream() {
                public boolean isFinished() { return bais.available() == 0; }
                public boolean isReady() { return true; }
                public void setReadListener(ReadListener readListener) {}
                public int read() { return bais.read(); }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new StringReader(body));
        }

        public String getBody() { return this.body; }
    }
}
