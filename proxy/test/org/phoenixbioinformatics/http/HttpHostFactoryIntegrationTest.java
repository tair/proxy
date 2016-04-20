/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import static org.junit.Assert.*;

import org.apache.http.HttpHost;
import org.junit.Test;


/**
 * CUT: HttpHostFactory; test getting a target host and partner id from the API
 * 
 * @author Robert J. Muller
 */
public class HttpHostFactoryIntegrationTest {
  private static final String TEST_SERVER_NAME = "test.arabidopsis.org";
  private static final String TEST_SCHEME = "https";
  private static final int TEST_PORT = -1;
  private static final String TEST_FORWARDED_HOST = "forward.arabidopsis.org";
  private static final String SOURCE_URI = "demotair.arabidopsis.org";
  private static final String TARGET_HOST = "http://back-test.arabidopsis.org";
  private static final String PARTNER_ID = "tair";

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#getTargetHost()}.
   */
  @Test
  public void testGetTargetHost() {
    HttpHostFactory factory =
      new HttpHostFactory(new ApiPartnerPattern(SOURCE_URI),
                          new TruePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
    assertTrue(factory != null);
    HttpHost host = factory.getTargetHost();
    assertTrue(host != null);
    String hostname = host.getHostName();
    String scheme = host.getSchemeName();
    String targetHost = scheme + "://" + hostname;
    assertTrue("Expected " + TARGET_HOST + " but got " + targetHost,
               TARGET_HOST.equals(targetHost));
  }

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#getTargetHost()}.
   */
  @Test
  public void testGetPartnerId() {
    HttpHostFactory factory =
      new HttpHostFactory(new ApiPartnerPattern(SOURCE_URI),
                          new TruePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
    assertTrue(factory != null);
    String id = factory.getPartnerId();
    assertTrue("Expected partner " + PARTNER_ID + " but got " + id,
               PARTNER_ID.equals(id));
  }

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#getTargetHost()}.
   */
  @Test
  public void testGetTargetHostWithSource() {
    ApiPartnerPattern pattern = new ApiPartnerPattern(null);
    HttpHostFactory factory =
      new HttpHostFactory(pattern,
                          new TruePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
    assertTrue(factory != null);
    pattern.setSourceUri(SOURCE_URI);
    HttpHost host = factory.getTargetHost();
    assertTrue(host != null);
    String hostname = host.getHostName();
    String scheme = host.getSchemeName();
    String targetHost = scheme + "://" + hostname;
    assertTrue("Expected " + TARGET_HOST + " but got " + targetHost,
               TARGET_HOST.equals(targetHost));
  }

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#getTargetHost()}.
   */
  @Test
  public void testGetPartnerIdWithSource() {
    ApiPartnerPattern pattern = new ApiPartnerPattern(null);
    HttpHostFactory factory =
      new HttpHostFactory(pattern,
                          new TruePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
    assertTrue(factory != null);
    pattern.setSourceUri(SOURCE_URI);
    String id = factory.getPartnerId();
    assertTrue("Expected partner " + PARTNER_ID + " but got " + id,
               PARTNER_ID.equals(id));
  }
}
