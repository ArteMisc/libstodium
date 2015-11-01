package eu.artemisc.strodium.Box;

/**
 * Box is a static class that maps all calls to the corresponding native
 * implementations. All the methods are crypto_box_* functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Box {
    public static final int KEYBYTES = 32;
    public static final int NONCEBYTES = 24;
    public static final int MACBYTES = 16;
}
