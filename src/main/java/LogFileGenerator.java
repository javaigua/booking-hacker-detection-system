import java.io.File;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.ZoneOffset;
import java.time.LocalDateTime;
import java.util.concurrent.ThreadLocalRandom;

public class LogFileGenerator {
  public static void main(String[] args) {
    BufferedWriter bufferedWriter = null;
    FileWriter fileWriter = null;
    
    try {
      ThreadLocalRandom r = ThreadLocalRandom.current();
      
      final String FILE_NAME = "sample-log.csv";
      File file = new File(FILE_NAME);
      
      fileWriter = new FileWriter(file.getAbsoluteFile(), true);
      bufferedWriter = new BufferedWriter(fileWriter);
      
      for(int i = 0; i < 850000; i++) {
        // file parts
        Long lineDate = LocalDateTime.now().atOffset(ZoneOffset.UTC).toInstant().toEpochMilli();
        String lineIp = new StringBuffer().append(r.nextInt(1, 256)).append(".").append(r.nextInt(1, 120))
          .append(".").append(r.nextInt(1, 2)).append(".").append(r.nextInt(1, 2)).toString();
        String lineAction = "SUCCESS";
        
        int indexMod = i % 5;
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
            .append("John.Smith.").append(i % 5).append(",")
            .append(lineAction)
            .toString());
        bufferedWriter.newLine();
      }
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
