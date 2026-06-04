package cc.blynk.server.internal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 19.09.18.
 *
 * FIX C-5: Replaced raw ObjectInputStream with a class-filtering subclass.
 * Raw ObjectInputStream.readObject() with no class whitelist is a well-known
 * Remote Code Execution vector (gadget chains via Apache Commons Collections etc.).
 * If an attacker can write a crafted file to the data folder, they could achieve RCE.
 * The FilteredObjectInputStream below only allows cc.blynk.** and safe JDK collections.
 */
public final class SerializationUtil {

    private final static Logger log = LogManager.getLogger(SerializationUtil.class);

    // FIX C-5: whitelist of package prefixes permitted during deserialization.
    // Covers: all Blynk domain classes (cc.blynk.*), ConcurrentHashMap and its
    // internal lock classes, HashMap, common primitives, and Java enums.
    // This prevents RCE via gadget chains while allowing legitimate Blynk data.
    private static final Set<String> ALLOWED_PACKAGES = Set.of(
            "cc.blynk.",
            // ConcurrentHashMap and its internal classes (segment locks etc.)
            "java.util.concurrent.ConcurrentHashMap",
            "java.util.concurrent.ConcurrentHashMap$",
            "java.util.concurrent.locks.ReentrantLock",
            "java.util.concurrent.locks.ReentrantLock$",
            "java.util.concurrent.locks.AbstractQueuedSynchronizer",
            "java.util.concurrent.locks.AbstractQueuedSynchronizer$",
            "java.util.concurrent.locks.AbstractOwnableSynchronizer",
            // Standard collections
            "java.util.HashMap",
            "java.util.HashMap$",
            "java.util.LinkedHashMap",
            "java.util.LinkedHashMap$",
            "java.util.ArrayList",
            "java.util.LinkedList",
            // Primitives and wrappers
            "java.lang.Number",
            "java.lang.Long",
            "java.lang.Integer",
            "java.lang.Double",
            "java.lang.Float",
            "java.lang.Short",
            "java.lang.Byte",
            "java.lang.Boolean",
            "java.lang.Character",
            "java.lang.String",
            // Enum support - Java serializes enum values via java.lang.Enum
            "java.lang.Enum",
            "java.lang.Object",
            // Arrays
            "["
    );

    private SerializationUtil() {
    }

    public static Object deserialize(Path path) {
        if (Files.exists(path)) {
            try {
                return deserializeObject(path);
            } catch (Exception e) {
                log.error("Failed to deserialize {}: {}", path, e.getMessage());
            }
        }
        return new ConcurrentHashMap<>();
    }

    public static void serialize(Path path, Map<?, ?> map) {
        if (map.size() > 0) {
            try {
                serializeObject(path, map);
            } catch (Exception e) {
                log.error("Failed to serialize to {}: {}", path, e.getMessage());
            }
        }
    }

    private static Object deserializeObject(Path path) throws IOException, ClassNotFoundException {
        try (InputStream is = Files.newInputStream(path);
             // FIX C-5: use filtering stream - blocks gadget-chain deserialization attacks
             ObjectInputStream objectinputstream = new FilteredObjectInputStream(is)) {
            return objectinputstream.readObject();
        }
    }

    private static void serializeObject(Path path, Object obj) throws IOException {
        try (OutputStream os = Files.newOutputStream(path);
             ObjectOutputStream oos = new ObjectOutputStream(os)) {
            oos.writeObject(obj);
        }
    }

    /**
     * FIX C-5: ObjectInputStream subclass that blocks deserialization of any class
     * not in the explicit whitelist. Prevents RCE via Java deserialization gadget chains.
     */
    private static final class FilteredObjectInputStream extends ObjectInputStream {

        FilteredObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            String className = desc.getName();
            boolean allowed = ALLOWED_PACKAGES.stream()
                    .anyMatch(pkg -> className.startsWith(pkg));
            if (!allowed) {
                log.error("Deserialization BLOCKED for class '{}' - not in whitelist. "
                        + "Possible deserialization attack.", className);
                throw new InvalidClassException(
                        "Unauthorized deserialization attempt for class: " + className);
            }
            return super.resolveClass(desc);
        }
    }
}
