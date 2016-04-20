/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import static org.junit.Assert.assertTrue;

import org.apache.http.HttpHost;
import org.junit.Test;


/**
 * CUT: HttpHostFactory
 * 
 * @author Robert J. Muller
 */
public class HttpHostFactoryTest {

  private static final String TEST_SERVER_NAME = "test.arabidopsis.org";
  private static final String TEST_SCHEME = "https";
  private static final int TEST_PORT = -1;
  private static final String TEST_FORWARDED_HOST = "forward.arabidopsis.org";
  private static final boolean TEST_PRESERVED_FLAG = true;
  private static final String SOURCE_URI = "www.arabidopsis.org";
  private static final String TARGET_HOST = "http://back-prod.arabidopsis.org";
  private static final String PARTNER_ID = "tair";

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#HttpHostFactory(javax.servlet.http.HttpServletRequest, boolean)}
   * .
   */
  @Test
  public void testHttpHostFactory() {
    HttpHostFactory factory =
      new HttpHostFactory(new TestPartnerPattern(SOURCE_URI),
                          new TruePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
    assertTrue(TEST_SERVER_NAME.equals(factory.getServerName()));
    assertTrue(TEST_SCHEME.equals(factory.getScheme()));
    assertTrue(TEST_PORT == factory.getPort());
    assertTrue(TEST_FORWARDED_HOST.equals(factory.getForwardedHost()));
    assertTrue(TEST_PRESERVED_FLAG == factory.getHostPreserved());
  }

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#getSourceHost()}.
   * Tests flag set for host preservation
   */
  @Test
  public void testGetSourceHostPreserved() {
    HttpHostFactory factory =
      new HttpHostFactory(new TestPartnerPattern(SOURCE_URI),
                          new TruePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
    HttpHost host = factory.getSourceHost();
    assertTrue(host != null);
    assertTrue(host.getHostName().equals(TEST_SERVER_NAME));
    assertTrue(host.getSchemeName().equals(TEST_SCHEME));
    assertTrue(host.getPort() == TEST_PORT);
  }

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#getSourceHost()}.
   * Tests flag not set for host preservation
   */
  @Test
  public void testGetSourceHostNotPreserved() {
    HttpHostFactory factory =
      new HttpHostFactory(new TestPartnerPattern(SOURCE_URI),
                          new FalsePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
    HttpHost host = factory.getSourceHost();
    assertTrue(host != null);
    assertTrue(host.getHostName().equals(TEST_FORWARDED_HOST));
    assertTrue(host.getSchemeName().equals(TEST_SCHEME));
    assertTrue(host.getPort() == TEST_PORT);
  }

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#getSourceHost()}.
   * Tests default HTTP port
   */
  @Test
  public void testGetSourceHostDefaultHttpPort() {
    HttpHostFactory factory =
      new HttpHostFactory(new TestPartnerPattern(SOURCE_URI),
                          new FalsePreservedProperty(),
                          "http",
                          TEST_SERVER_NAME,
                          -1,
                          TEST_FORWARDED_HOST);
    HttpHost host = factory.getSourceHost();
    assertTrue("Expected port -1, got port " + host.getPort(),
               host.getPort() == -1);
  }

  /**
   * Test method for
   * {@link org.phoenixbioinformatics.http.HttpHostFactory#getTargetHost()}.
   */
  @Test
  public void testGetTargetHost() {
    HttpHostFactory factory =
      new HttpHostFactory(new TestPartnerPattern(SOURCE_URI),
                          new TruePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
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
      new HttpHostFactory(new TestPartnerPattern(SOURCE_URI),
                          new TruePreservedProperty(),
                          TEST_SCHEME,
                          TEST_SERVER_NAME,
                          TEST_PORT,
                          TEST_FORWARDED_HOST);
    String id = factory.getPartnerId();
    assertTrue("Expected partner " + PARTNER_ID + " but got " + id,
               PARTNER_ID.equals(id));
  }
}
