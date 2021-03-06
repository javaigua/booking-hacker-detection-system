package com.booking.security.hackertest.detector.util;

import java.io.File;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.ZoneOffset;
import java.time.LocalDateTime;
import java.util.concurrent.ThreadLocalRandom;

public class LogFileGenerator {
  public static void main(String[] args) {
    // Usage and default param values
    final String DEFAULT_FILE_NAME = "login.log.sample";
    String fileName = DEFAULT_FILE_NAME;
    if(args.length != 0 && args.length > 1) {
      throw new IllegalArgumentException("Usage: LogFileGenerator [path]");
    } else if(args.length == 1) {
      fileName = args[0];
    }
    
    BufferedWriter bufferedWriter = null;
    FileWriter fileWriter = null;
    
    try {
      System.out.println("\n status: log_file_generaration, file: " + fileName);
      ThreadLocalRandom r = ThreadLocalRandom.current();
      File file = new File(fileName);
      
      fileWriter = new FileWriter(file.getAbsoluteFile(), true);
      bufferedWriter = new BufferedWriter(fileWriter);
      
      int rows = 1000000;
      for(int i = 0; i < rows; i++) {
        // file parts
        Long lineDate = LocalDateTime.now().atOffset(ZoneOffset.UTC).toInstant().toEpochMilli();
        String lineIp = new StringBuffer().append(r.nextInt(1, 256)).append(".").append(r.nextInt(1, 128))
          .append(".").append(r.nextInt(1, 2)).append(".").append(r.nextInt(1, 2)).toString();
        String lineAction = "SUCCESS";
        
        int indexMod = (i % 5);
        if (indexMod == 0) {
          lineAction = "FAILURE";
          bufferedWriter.flush();
        }
        
        // Log line example
        // 1507365137,187.218.83.136,John.Smith,SUCCESS
        bufferedWriter.write(
          new StringBuffer()
            .append(lineDate).append(",")
            .append(lineIp).append(",")
            .append("John.Smith.").append((i % 10)).append(",")
            .append(lineAction)
            .toString());
        bufferedWriter.newLine();
      }
      System.out.println(" status: log_file_generation_finished, rows: " + rows + "\n");
    } catch (Exception e) {
      System.out.println(e.toString());
    } finally {
      try {
        if (bufferedWriter != null) {
          bufferedWriter.close();
        }      
        if (fileWriter != null) {
          fileWriter.close();
        }
      }
      catch (Exception e) { /* Ignore */ }
    }
  }
}
