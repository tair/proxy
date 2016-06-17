package org.phoenixbioinformatics.api;

import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.phoenixbioinformatics.properties.ProxyProperties;

public class EmailUtility {

	private static Properties mailServerProperties;
	private static Session mailSession;
	private static MimeMessage message;

	private static final String SEND_EMAIL_ERROR = "Error sending metering email to ";
	private static final Logger logger = LogManager.getLogger(EmailUtility.class);

//	private static Session createSession() {
//		Authenticator authenticator = new Authenticator() {
//			@Override
//			protected PasswordAuthentication getPasswordAuthentication() {
//				return new PasswordAuthentication(ProxyProperties.getProperty("metering.email.username"), ProxyProperties.getProperty("metering.email.password"));
//			}
//		};
//		Session session = Session.getDefaultInstance(new Properties(), authenticator);
//		return session;
//	}

	public static void send(String to, String from, String subject, String body) {
		
		// setup Mail Server Properties //TODO
		mailServerProperties = System.getProperties();
		mailServerProperties.setProperty("mail.smtp.host", ProxyProperties.getProperty("metering.email.host")); //localhost
		mailServerProperties.put("mail.smtp.port", ProxyProperties.getProperty("metering.email.port")); // for gmail 587
		mailServerProperties.put("mail.smtp.auth", "true");
		mailServerProperties.put("mail.smtp.starttls.enable", "true");

		try {
			// create mail session
			mailSession = Session.getDefaultInstance(mailServerProperties, null);
			// or
			// mailSession = createSession();
			message = new MimeMessage(mailSession);
			message.setFrom(new InternetAddress(from));

			message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));
			message.addRecipient(Message.RecipientType.CC, new InternetAddress(ProxyProperties.getProperty("metering.email.cc")));
			message.setSubject(subject);
			message.setContent(body, "text/html");

			Transport transport = mailSession.getTransport("smtp");

			// Enter your correct gmail UserID and Password
			// if you have 2FA enabled then provide App Specific Password
			transport.connect("smtp.gmail.com", ProxyProperties.getProperty("metering.email.username"), ProxyProperties.getProperty("metering.email.password"));// TODO
			transport.sendMessage(message, message.getAllRecipients());
			transport.close();

			// or just
			// Transport.send(message);
		}
		catch (MessagingException e) {
			logger.error(SEND_EMAIL_ERROR + to, e);
		}
	}
}
