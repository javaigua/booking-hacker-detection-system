import scala.concurrent.Future;
import scala.concurrent.ExecutionContext;
import scala.concurrent.duration.Duration;
import scala.concurrent.duration.FiniteDuration;

import java.util.Arrays;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletionStage;

import akka.Done;
import akka.NotUsed;
import akka.util.Timeout;
import akka.util.ByteString;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.ActorNotFound;
import akka.dispatch.OnComplete;
import akka.pattern.Patterns;
import akka.actor.ActorSystem;
import akka.stream.Materializer;
import akka.stream.ActorMaterializer;
import akka.stream.javadsl.Sink;
import akka.stream.javadsl.Source;
import akka.stream.alpakka.csv.javadsl.CsvParsing;
import akka.stream.alpakka.file.javadsl.FileTailSource;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

public class FileTailSourceTest {

  public static void main(String... args) {
    if(args.length != 1) throw new IllegalArgumentException("Usage: FileTailSourceTest [path]");
    final String path = args[0];

    final ActorSystem system = ActorSystem.create();
    final Materializer materializer = ActorMaterializer.create(system);

    final FileSystem fs = FileSystems.getDefault();
    final FiniteDuration pollingInterval = FiniteDuration.create(250, TimeUnit.MILLISECONDS);
    final int maxLineSize = 8192;

    final Source<String, NotUsed> lines =
      akka.stream.alpakka.file.javadsl.FileTailSource.createLines(fs.getPath(path), maxLineSize, pollingInterval);

    lines.runForeach((line) -> System.out.println(line), materializer);
  }
  
}
