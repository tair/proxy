/*
 * Copyright (c) 2015 Phoenix Bioinformatics Corporation. All rights reserved.
 */

package org.phoenixbioinformatics.proxy;

import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight utility for accumulating named timing segments across a request
 * lifecycle. Produces a single summary string for logging.
 */
public class RequestTimer {
  private final long startTime;
  private final List<String> segments = new ArrayList<String>();
  private long lastMark;

  public RequestTimer() {
    this.startTime = System.currentTimeMillis();
    this.lastMark = startTime;
  }

  public void mark(String label) {
    long now = System.currentTimeMillis();
    segments.add(label + "=" + (now - lastMark) + "ms");
    lastMark = now;
  }

  public long totalMs() {
    return System.currentTimeMillis() - startTime;
  }

  public String summary() {
    return "total=" + totalMs() + "ms [" + join(segments, ", ") + "]";
  }

  private static String join(List<String> list, String delimiter) {
    if (list == null || list.isEmpty()) {
      return "";
    }
    StringBuilder sb = new StringBuilder(list.get(0));
    for (int i = 1; i < list.size(); i++) {
      sb.append(delimiter).append(list.get(i));
    }
    return sb.toString();
  }
}
