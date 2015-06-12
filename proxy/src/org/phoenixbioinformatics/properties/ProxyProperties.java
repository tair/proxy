/**
 * 
 */
package org.phoenixbioinformatics.properties;


import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.phoenixbioinformatics.proxy.ProxyRequest;


/**
 * A utility class that loads the proxy properties file and makes the properties
 * available by key.
 * 
 * @author Robert J. Muller
 */
public class ProxyProperties {
  /** logger for this class */
  private static final Logger logger = LogManager.getLogger(ProxyProperties.class);

  // Error messages
  private static final String CLOSE_ERROR =
    "Error closing property stream for proxy properties";
  private static final String IO_LOAD_ERROR =
    "Could not load proxy properties file (IO Exception)";
  private static final String LOAD_ERROR =
    "Could not load proxy properties file";

  /** name of the property file */
  private static final String PROPERTY_FILE =
    "/org/phoenixbioinformatics/properties/proxy.properties";

  /** Properties object for proxy properties */
  private static final Properties PROXY_PROPERTIES = new Properties();
  /** stream for property input */
  private static InputStream proxyStream = null;

  // static block that loads the proxy properties file
  static {
    try {
      proxyStream = ProxyRequest.class.getResourceAsStream(PROPERTY_FILE);
      // load a properties file
      PROXY_PROPERTIES.load(proxyStream);
    } catch (FileNotFoundException e) {
      logger.error(LOAD_ERROR, e);
    } catch (IOException e) {
      logger.error(IO_LOAD_ERROR, e);
    } finally {
      if (proxyStream != null) {
        try {
          proxyStream.close();
        } catch (IOException e) {
          logger.error(CLOSE_ERROR, e);
        }
      }
    }
  }

  /**
   * Get the proxy property identified by the key.
   * 
   * @param key the key with which to look up the property
   * @return the String property value or null if there is no property
   */
  public static String getProperty(String key) {
    return PROXY_PROPERTIES.getProperty(key);
  }

  /**
   * Get the proxy property identified by the key or the specified default value
   * if no property is found.
   * 
   * @param key the key with which to look up the property
   * @param defaultValue the value to return if there is no instance of the key
   * @return the String property value
   */
  public static String getProperty(String key, String defaultValue) {
    return PROXY_PROPERTIES.getProperty(key, defaultValue);
  }

}
