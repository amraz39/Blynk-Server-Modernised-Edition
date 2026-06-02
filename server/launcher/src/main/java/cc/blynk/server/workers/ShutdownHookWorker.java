package cc.blynk.server.workers;

import cc.blynk.server.Holder;
import cc.blynk.server.servers.BaseServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.ScheduledExecutorService;

/**
 * Used to close and store all important info to disk.
 *
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 25.03.15.
 */
public class ShutdownHookWorker implements Runnable {

    private static final Logger log = LogManager.getLogger(ShutdownHookWorker.class);

    private final BaseServer[] servers;
    private final Holder holder;
    private final ProfileSaverWorker profileSaverWorker;
    private final ScheduledExecutorService scheduler;

    public ShutdownHookWorker(BaseServer[] servers, Holder holder,
                              ScheduledExecutorService scheduler,
                              ProfileSaverWorker profileSaverWorker) {
        this.servers = servers;
        this.holder = holder;
        this.profileSaverWorker = profileSaverWorker;
        this.scheduler = scheduler;
    }

    @Override
    public void run() {
        // FIX: replaced System.out.println with Log4j2 so shutdown messages appear in log files
        log.info("Catch shutdown hook.");
        log.info("Stopping servers...");

        for (var server : servers) {
            try {
                server.close().sync();
            } catch (Throwable t) {
                log.error("Error on server shutdown.", t.getCause());
            }
        }

        log.info("Stopping scheduler...");
        scheduler.shutdown();

        try {
            holder.close();
        } catch (Exception e) {
            log.error("Error stopping holder.", e);
        }

        log.info("Saving user profiles...");
        profileSaverWorker.close();

        log.info("Shutdown complete.");
    }

}
