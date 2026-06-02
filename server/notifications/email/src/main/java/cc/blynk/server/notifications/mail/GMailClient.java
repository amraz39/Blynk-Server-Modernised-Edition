package cc.blynk.server.notifications.mail;

import cc.blynk.utils.properties.MailProperties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.activation.DataHandler;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

/**
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 14.09.16.
 *
 * FIX: improved error diagnostics, explicit TLS properties, writetimeout.
 * NOTE: Gmail requires an App Password (not your account password) since 2022.
 *       Generate at: https://myaccount.google.com/apppasswords
 */
public class GMailClient implements MailClient {

    private static final Logger log = LogManager.getLogger(GMailClient.class);

    private final Session session;
    private final InternetAddress from;

    GMailClient(MailProperties mailProperties) {
        String username = mailProperties.getSMTPUsername();
        String password = mailProperties.getSMTPPassword();

        // FIX: ensure critical SSL/TLS properties are set even if missing from mail.properties
        if (mailProperties.getProperty("mail.smtp.ssl.protocols") == null) {
            mailProperties.put("mail.smtp.ssl.protocols", "TLSv1.2 TLSv1.3");
        }
        if (mailProperties.getProperty("mail.smtp.starttls.required") == null) {
            mailProperties.put("mail.smtp.starttls.required", "true");
        }
        // FIX: writetimeout prevents silent hangs when SMTP server is slow
        if (mailProperties.getProperty("mail.smtp.writetimeout") == null) {
            mailProperties.put("mail.smtp.writetimeout", "30000");
        }

        log.info("Initializing Gmail SMTP transport. Username: {}. Host: {}:{}",
                username, mailProperties.getSMTPHost(), mailProperties.getSMTPort());

        // FIX: warn early if credentials look unconfigured — gives a clear message
        // instead of a cryptic "network unavailable" error from the JVM SSL stack
        if (username == null || username.isEmpty() || username.equals("YOUR_GMAIL_ADDRESS@gmail.com")) {
            log.error("⚠ mail.smtp.username is not configured in mail.properties! "
                    + "Email sending will fail. Edit mail.properties and set your Gmail address "
                    + "and a Gmail App Password (not your account password). "
                    + "Generate an App Password at: https://myaccount.google.com/apppasswords");
        }
        if (password == null || password.isEmpty() || password.equals("YOUR_16_CHAR_APP_PASSWORD")) {
            log.error("⚠ mail.smtp.password is not configured in mail.properties! "
                    + "Email sending will fail. Use a Gmail App Password, NOT your Gmail account password. "
                    + "Google disabled plain-password login in 2022. "
                    + "Generate at: https://myaccount.google.com/apppasswords");
        }

        this.session = Session.getInstance(mailProperties, new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });

        try {
            this.from = new InternetAddress(username);
        } catch (AddressException e) {
            throw new RuntimeException("Error initializing GMailClient: " + e.getMessage());
        }
    }

    @Override
    public void sendText(String to, String subj, String body) throws Exception {
        send(to, subj, body, TEXT_PLAIN_CHARSET_UTF_8);
    }

    @Override
    public void sendHtml(String to, String subj, String body) throws Exception {
        send(to, subj, body, TEXT_HTML_CHARSET_UTF_8);
    }

    @Override
    public void sendHtmlWithAttachment(String to, String subj, String body,
                                       QrHolder[] attachmentData) throws Exception {
        MimeMessage message = new MimeMessage(session);
        message.setFrom(from);
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
        message.setSubject(subj, "UTF-8");

        Multipart multipart = new MimeMultipart();

        MimeBodyPart bodyMessagePart = new MimeBodyPart();
        bodyMessagePart.setContent(body, TEXT_HTML_CHARSET_UTF_8);
        multipart.addBodyPart(bodyMessagePart);

        attachQRs(multipart, attachmentData);
        attachCSV(multipart, attachmentData);

        message.setContent(multipart);

        sendMessage(message, to);
    }

    private void attachCSV(Multipart multipart, QrHolder[] attachmentData) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (QrHolder qrHolder : attachmentData) {
            sb.append(qrHolder.token)
              .append(",")
              .append(qrHolder.deviceId)
              .append(",")
              .append(qrHolder.dashId)
              .append("\n");
        }
        MimeBodyPart attachmentsPart = new MimeBodyPart();
        ByteArrayDataSource source = new ByteArrayDataSource(sb.toString(), "text/csv");
        attachmentsPart.setDataHandler(new DataHandler(source));
        attachmentsPart.setFileName("tokens.csv");
        multipart.addBodyPart(attachmentsPart);
    }

    private void attachQRs(Multipart multipart, QrHolder[] attachmentData) throws Exception {
        for (QrHolder qrHolder : attachmentData) {
            MimeBodyPart attachmentsPart = new MimeBodyPart();
            ByteArrayDataSource source = new ByteArrayDataSource(qrHolder.data, "image/jpeg");
            attachmentsPart.setDataHandler(new DataHandler(source));
            attachmentsPart.setFileName(qrHolder.makeQRFilename());
            multipart.addBodyPart(attachmentsPart);
        }
    }

    private void send(String to, String subj, String body, String contentType) throws Exception {
        MimeMessage message = new MimeMessage(session);
        message.setFrom(from);
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
        message.setSubject(subj, "UTF-8");
        message.setContent(body, contentType);
        sendMessage(message, to);
    }

    // FIX: extracted common send path with actionable error diagnostics.
    // The original code surfaced javax.mail internal errors as "check your network"
    // because the root cause (wrong password, missing App Password, SSL mismatch)
    // was swallowed or logged without context at the call site.
    private void sendMessage(MimeMessage message, String to) throws Exception {
        try {
            Transport.send(message);
            log.trace("Mail to {} was sent.", to);
        } catch (MessagingException e) {
            String cause = e.getMessage();
            if (cause != null && (cause.contains("535") || cause.contains("Username and Password not accepted")
                    || cause.contains("Authentication"))) {
                log.error("Gmail authentication failed sending to {}. "
                        + "Make sure you are using a Gmail App Password "
                        + "(NOT your account password) in mail.properties. "
                        + "Google disabled plain-password SMTP login in May 2022. "
                        + "Generate an App Password at: https://myaccount.google.com/apppasswords. "
                        + "Raw error: {}", to, cause);
            } else if (cause != null && (cause.contains("SSL") || cause.contains("TLS")
                    || cause.contains("handshake") || cause.contains("PKIX"))) {
                log.error("SSL/TLS error sending email to {}. "
                        + "Ensure mail.smtp.ssl.trust=smtp.gmail.com and "
                        + "mail.smtp.ssl.protocols=TLSv1.2 TLSv1.3 are set in mail.properties. "
                        + "Raw error: {}", to, cause);
            } else if (cause != null && cause.contains("timeout")) {
                log.error("Timeout connecting to SMTP server while sending to {}. "
                        + "Check mail.smtp.host and mail.smtp.port. "
                        + "Raw error: {}", to, cause);
            } else {
                log.error("Failed to send email to {}. Raw error: {}", to, cause, e);
            }
            throw e;
        }
    }
}
