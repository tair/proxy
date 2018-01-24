/**
* Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.proxy;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;

import org.junit.Test;

/**
 * 
 * @author Robert J. Muller
 */
public class ProxyTest {

  /**
   * Test method for {@link org.phoenixbioinformatics.proxy.Proxy#canonicalizeIpAddress(java.lang.String)}.
   */
  @Test
  public void testCanonicalizeIpAddress() {
    ArrayList<String> ip1 = Proxy.canonicalizeIpAddress("192.178.255.255");
    assertTrue("Bad string 1: " + ip1, ip1.equals("192.178.255.255"));
    ArrayList<String> ip2 = Proxy.canonicalizeIpAddress(" 192.178.255.255 ");
    assertTrue("Bad string 2: " + ip2, ip2.equals("192.178.255.255"));
    ArrayList<String> ip3 = Proxy.canonicalizeIpAddress("198.172.54.34,192.178.255.255");
    assertTrue("Bad string 3: " + ip3, ip3.equals("192.178.255.255"));
    ArrayList<String> ip4 = Proxy.canonicalizeIpAddress("255.255.255.255,198.172.54.34,192.178.255.255");
    assertTrue("Bad string 4: " + ip4, ip4.equals("192.178.255.255"));
  }
}
