package cc.blynk.server.core;

import cc.blynk.utils.BlynkTPFactory;

import java.io.Closeable;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Wrapper around ThreadPoolExecutor that should perform blocking IO operations.
 * Due to async nature of netty performing Blocking operations withing netty pipeline
 * will cause performance issues. So Blocking operations should always
 * executed via this wrapper.
 *
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 07.04.15.
 */
public class BlockingIOProcessor implements Closeable {

    private static final int MINIMUM_ALLOWED_POOL_SIZE = 3;

    //pool for messaging
    public final ThreadPoolExecutor messagingExecutor;

    //DB pool is needed as in case DB goes down messaging still should work
    public final ThreadPoolExecutor dbExecutor;

    //DB pool is needed as in case DB goes down messaging still should work
    public final ThreadPoolExecutor dbReportingExecutor;

    public final ThreadPoolExecutor dbGetServerExecutor;

    //separate pool for history graph data
    public final ThreadPoolExecutor historyExecutor;

    public BlockingIOProcessor(int poolSize, int maxQueueSize) {
        //pool size can't be less than 3.
        poolSize = Math.max(MINIMUM_ALLOWED_POOL_SIZE, poolSize);

        // Use Math.max to avoid integer-division truncation producing 0 or 1-thread pools
        int messagingCore = Math.max(2, poolSize / 4);
        int messagingMax  = Math.max(2, poolSize / 3);
        this.messagingExecutor = new ThreadPoolExecutor(
                messagingCore, messagingMax,
                2L, TimeUnit.MINUTES,
                new ArrayBlockingQueue<>(maxQueueSize),
                BlynkTPFactory.build("Messaging")
        );

        this.dbExecutor = new ThreadPoolExecutor(
                Math.max(1, poolSize / 3),
                Math.max(2, poolSize / 2), 2L,
                TimeUnit.MINUTES,
                new ArrayBlockingQueue<>(250),
                BlynkTPFactory.build("db"));
        //local server doesn't use DB usually, so this thread may be not necessary
        this.dbExecutor.allowCoreThreadTimeOut(true);

        // Dedicated single-thread pool for reporting DB writes; isolated so a
        // main-DB outage does not block reporting and vice-versa.
        this.dbReportingExecutor = new ThreadPoolExecutor(
                1,
                1, 2L,
                TimeUnit.MINUTES,
                new ArrayBlockingQueue<>(100),
                BlynkTPFactory.build("reporting-db"));

        this.dbGetServerExecutor = new ThreadPoolExecutor(poolSize, poolSize, 2L,
                TimeUnit.MINUTES, new ArrayBlockingQueue<>(250),
                BlynkTPFactory.build("getServer"));

        this.historyExecutor = new ThreadPoolExecutor(
                Math.max(1, poolSize / 4), Math.max(2, poolSize / 2), 2L,
                TimeUnit.MINUTES, new ArrayBlockingQueue<>(250),
                BlynkTPFactory.build("history"));
    }

    public void execute(Runnable task) {
        messagingExecutor.execute(task);
    }

    public void executeDB(Runnable task) {
        dbExecutor.execute(task);
    }

    // FIX: was incorrectly routing to dbExecutor; now correctly uses dbReportingExecutor
    public void executeReportingDB(Runnable task) {
        dbReportingExecutor.execute(task);
    }

    public void executeHistory(Runnable task) {
        historyExecutor.execute(task);
    }

    public void executeDBGetServer(Runnable task) {
        dbGetServerExecutor.execute(task);
    }

    @Override
    public void close() {
        dbExecutor.shutdown();
        dbReportingExecutor.shutdown(); // FIX: was missing, leaked thread on shutdown
        messagingExecutor.shutdown();
        historyExecutor.shutdown();
        dbGetServerExecutor.shutdown();
    }
}
