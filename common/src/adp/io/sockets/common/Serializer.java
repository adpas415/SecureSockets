package adp.io.sockets.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Serializer {

    public static Object deserialize(byte[] serializedObjected) {

        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedObjected);
             ObjectInputStream objectInputStream = new ObjectInputStream(bis)) {

            return objectInputStream.readObject();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;

    }

    public static byte[] serialize(Object objectToSerialize) {

        byte[] toReturn;

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream os = new ObjectOutputStream(bos)) {

            os.writeObject(objectToSerialize);
            toReturn = bos.toByteArray();

            return toReturn;

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
            return new byte[0];
        }

    }

}
