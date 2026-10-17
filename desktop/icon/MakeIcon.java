import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import javax.imageio.ImageIO;

/**
 * Renders the Wing mark (three feather strokes on an azure tile) to the
 * PNGs the desktop app uses and packs them into a Windows .ico.
 *
 * Run from the repo root:  java desktop/icon/MakeIcon.java
 * The Apple icons (the macOS .icns and the iOS app icon) come from
 *                          java desktop/icon/MakeIcon.java apple
 */
public class MakeIcon {
    static final Color AZURE = new Color(0x24548F);
    static final Color AZURE_DEEP = new Color(0x16386B);
    static final Color PAPER = new Color(0xFDFBF6);

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("apple")) {
            writeApple();
            return;
        }
        File dir = new File("desktop/icon");
        dir.mkdirs();
        File res = new File("desktop/src/main/resources/icon");
        res.mkdirs();

        int[] sizes = {16, 24, 32, 48, 64, 128, 256};
        ByteArrayOutputStream ico = new ByteArrayOutputStream();
        DataOutputStream header = new DataOutputStream(ico);
        header.writeShort(Short.reverseBytes((short) 0));
        header.writeShort(Short.reverseBytes((short) 1));
        header.writeShort(Short.reverseBytes((short) sizes.length));

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int offset = 6 + 16 * sizes.length;
        for (int size : sizes) {
            byte[] png = render(size, true);
            header.writeByte(size == 256 ? 0 : size);
            header.writeByte(size == 256 ? 0 : size);
            header.writeByte(0);
            header.writeByte(0);
            header.writeShort(Short.reverseBytes((short) 1));
            header.writeShort(Short.reverseBytes((short) 32));
            header.writeInt(Integer.reverseBytes(png.length));
            header.writeInt(Integer.reverseBytes(offset));
            offset += png.length;
            body.write(png);
        }
        try (FileOutputStream out = new FileOutputStream(new File(dir, "mythaia.ico"))) {
            ico.writeTo(out);
            body.writeTo(out);
        }
        Files.write(new File(res, "mythaia_256.png").toPath(), render(256, true));
        Files.write(new File(res, "mythaia_tray.png").toPath(), render(64, true));
        Files.write(new File(res, "mythaia_tray_off.png").toPath(), renderTile(64, new Color(0x4E5568), new Color(0x2F3646)));
        Files.write(new File(res, "mythaia_mark_paper.png").toPath(), renderMark(256, PAPER));
        Files.write(new File(res, "mythaia_mark_azure.png").toPath(), renderMark(256, AZURE));
        System.out.println("icons written");
    }

    /**
     * macOS: the tile inset on a transparent canvas the way Apple's icon grid
     * has it (824 of 1024), packed as PNG entries into an .icns.
     * iOS: one opaque 1024 square; the system rounds the corners itself.
     */
    static void writeApple() throws Exception {
        String[] types = {"ic11", "ic12", "ic07", "ic08", "ic13", "ic09", "ic14", "ic10"};
        int[] sizes = {32, 64, 128, 256, 256, 512, 512, 1024};
        ByteArrayOutputStream entries = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(entries);
        for (int i = 0; i < types.length; i++) {
            byte[] png = renderMac(sizes[i]);
            out.writeBytes(types[i]);
            out.writeInt(png.length + 8);
            out.write(png);
        }
        try (DataOutputStream icns = new DataOutputStream(new FileOutputStream(new File("desktop/icon/mythaia.icns")))) {
            icns.writeBytes("icns");
            icns.writeInt(entries.size() + 8);
            entries.writeTo(icns);
        }
        File ios = new File("ios/Mythaia/Assets.xcassets/AppIcon.appiconset");
        ios.mkdirs();
        Files.write(new File(ios, "AppIcon-1024.png").toPath(), renderSquare(1024));
        System.out.println("apple icons written");
    }

    static byte[] renderMac(int size) throws Exception {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        float tile = size * 824f / 1024f;
        float margin = (size - tile) / 2f;
        float radius = tile * 0.45f;
        g.setPaint(new java.awt.GradientPaint(margin, margin, AZURE, margin + tile, margin + tile, AZURE_DEEP));
        g.fill(new RoundRectangle2D.Float(margin, margin, tile, tile, radius, radius));
        g.translate(margin, margin);
        drawMark(g, Math.round(tile), tile * 0.16f, PAPER);
        g.dispose();
        return png(img);
    }

    static byte[] renderSquare(int size) throws Exception {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        g.setPaint(new java.awt.GradientPaint(0, 0, AZURE, size, size, AZURE_DEEP));
        g.fillRect(0, 0, size, size);
        drawMark(g, size, size * 0.17f, PAPER);
        g.dispose();
        return png(img);
    }

    /** The mark on a tile of the given colours (the tray's "off" state is slate). */
    static byte[] renderTile(int size, Color from, Color to) throws Exception {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        float radius = size * 0.22f;
        g.setPaint(new java.awt.GradientPaint(0, 0, from, size, size, to));
        g.fill(new RoundRectangle2D.Float(0, 0, size, size, radius, radius));
        drawMark(g, size, size * 0.14f, PAPER);
        g.dispose();
        return png(img);
    }

    /** The mark on a rounded azure tile. */
    static byte[] render(int size, boolean tile) throws Exception {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        if (tile) {
            float radius = size * 0.22f;
            g.setPaint(new java.awt.GradientPaint(0, 0, AZURE, size, size, AZURE_DEEP));
            g.fill(new RoundRectangle2D.Float(0, 0, size, size, radius, radius));
        }
        drawMark(g, size, size * 0.14f, PAPER);
        g.dispose();
        return png(img);
    }

    static byte[] renderMark(int size, Color color) throws Exception {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        drawMark(g, size, 0, color);
        g.dispose();
        return png(img);
    }

    /** Three quad-curve feathers from (20,82) in a 100x100 box, as in WingMark.kt. */
    static void drawMark(Graphics2D g, int size, float inset, Color color) {
        float s = (size - 2 * inset) / 100f;
        g.setColor(color);
        feather(g, s, inset, 21f, 32f, 82f, 20f, 8.5f);
        feather(g, s, inset, 29f, 47f, 69f, 38f, 8.0f);
        feather(g, s, inset, 36f, 61f, 57f, 55f, 7.5f);
    }

    static void feather(Graphics2D g, float s, float inset, float cx, float cy, float ex, float ey, float width) {
        Path2D.Float path = new Path2D.Float();
        path.moveTo(inset + 20f * s, inset + 82f * s);
        path.quadTo(inset + cx * s, inset + cy * s, inset + ex * s, inset + ey * s);
        g.setStroke(new BasicStroke(width * s, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g.draw(path);
    }

    static byte[] png(BufferedImage img) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return out.toByteArray();
    }
}
