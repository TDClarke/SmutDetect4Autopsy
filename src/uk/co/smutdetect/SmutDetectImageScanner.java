/**
 * SmutDetect
 * Copyright (C) 2014 Rajmund Witt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package uk.co.smutdetect;

import java.awt.image.BufferedImage;
import java.awt.image.DataBuffer;
import java.awt.image.DataBufferByte;
import java.awt.image.DataBufferInt;
import java.awt.image.PixelInterleavedSampleModel;
import java.awt.image.SampleModel;
import java.awt.image.SinglePixelPackedSampleModel;
import java.awt.image.WritableRaster;
import java.io.InputStream;
import java.util.Iterator;
import java.util.logging.Level;
import javax.imageio.ImageIO;
import javax.imageio.ImageReadParam;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.MemoryCacheImageInputStream;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.ReadContentInputStream;

/**
 * Scans an image file for skin-tone pixels.
 *
 * Differences from the original implementation:
 *  - decodes via ImageReader on a memory-backed stream (ImageIO.read(InputStream)
 *    uses a disk cache by default, i.e. a temp file per image) and closes
 *    every stream and reader;
 *  - for the common raster layouts (TYPE_3BYTE_BGR, TYPE_INT_RGB,
 *    TYPE_INT_ARGB) the pixels are read straight from the raster, which avoids
 *    BufferedImage.getRGB (the most expensive step by far). Other layouts fall
 *    back to bulk getRGB, one call per row;
 *  - the skin tests are branchless integer loops (SkinToneCounter) that the
 *    JIT can vectorise, exactly equivalent to the reference detectors;
 *  - dimensions are checked before decoding, and OutOfMemoryError is caught so
 *    one oversized image cannot kill an ingest thread;
 *  - failures are logged with the file name and exception;
 *  - optional sub-sampling to scan a reduced image.
 *
 * Only the first frame of animated GIFs is scanned.
 *
 * @author Rajmund Witt <code@4ensics.co.uk>
 */
public abstract class SmutDetectImageScanner {

    private static final Logger logger_ = Logger.getLogger(
            SmutDetectImageScanner.class.getName());

    /** Images whose (decoded) pixel count exceeds this are skipped. */
    public static final long MAX_PIXELS = 100_000_000L;

    private static final int NUDE_MAX_DIM = 1024;
    
    /**
     * Scans the full-resolution image (same behaviour as the original module).
     */
    public static SmutDetectCategorisedImage scanImage(AbstractFile file) {
        return scanImage(file, 0, true);
    }

    private static NudityClassifier.Result classifyNudity(BufferedImage img, int bw, int bh) {
        try {
            final int step = Math.max(1, Math.max(bw, bh) / NUDE_MAX_DIM);
            final int sw = (bw + step - 1) / step;
            final int sh = (bh + step - 1) / step;
            final int[] argb = new int[sw * sh];
            final int[] row = new int[bw];
            int k = 0;
            for (int y = 0; y < bh; y += step) {
                img.getRGB(0, y, bw, 1, row, 0, bw);
                for (int x = 0; x < bw; x += step) {
                    argb[k++] = row[x];
                }
            }
        return NudityClassifier.classify(argb, sw, sh);
        }
        catch (RuntimeException | OutOfMemoryError e) {
            logger_.log(Level.WARNING, "Nudity classification failed", e);
            return NudityClassifier.Result.ERROR;
        }
    }
    
    /**
     * @param file        the file to scan
     * @param maxScanDim  if greater than 0, the image is decoded sub-sampled so
     *                    its longer side is roughly at most this many pixels
     *                    (e.g. 512). This cuts memory and pixel-loop work but
     *                    percentages become estimates and may differ by a
     *                    point or two from a full scan. 0 scans every pixel.
     * @return the result, or null if the file could not be read as an image
     */
    public static SmutDetectCategorisedImage scanImage(AbstractFile file, int maxScanDim, boolean detectNudity) {
        try (InputStream in = new ReadContentInputStream(file);
                ImageInputStream iis = new MemoryCacheImageInputStream(in)) {

            Iterator<ImageReader> readers = ImageIO.getImageReaders(iis);
            if (!readers.hasNext()) {
                return null; // not a format ImageIO can decode
            }

            ImageReader reader = readers.next();
            try {
                reader.setInput(iis, false, true); // random access, ignore metadata

                final long w = reader.getWidth(0);
                final long h = reader.getHeight(0);

                ImageReadParam param = reader.getDefaultReadParam();
                int step = 1;
                if (maxScanDim > 0) {
                    step = (int) Math.max(1L, Math.max(w, h) / maxScanDim);
                    if (step > 1) {
                        param.setSourceSubsampling(step, step, 0, 0);
                    }
                }

                // size of what will actually be decoded
                final long decodedPixels = ((w + step - 1) / step) * ((h + step - 1) / step);
                if (decodedPixels > MAX_PIXELS) {
                    logger_.log(Level.INFO, "Skipping oversized image " + file.getName()
                            + " (id=" + file.getId() + ", " + w + "x" + h + ")");
                    return null;
                }

                BufferedImage img = reader.read(0, param);
                if (img == null) {
                    return null;
                }

                final int bw = img.getWidth();
                final int bh = img.getHeight();
                final long[] hits = new long[2]; // [0] = RGB, [1] = YCbCr

                if (!countFromRaster(img, bw, bh, hits)) {
                    final int[] row = new int[bw];
                    for (int y = 0; y < bh; y++) {
                        img.getRGB(0, y, bw, 1, row, 0, bw); // one bulk call per row
                        SkinToneCounter.countPacked(row, 0, bw, hits);
                    }
                }
                final long rgbHits = hits[0];
                final long yccHits = hits[1];

                SmutDetectCategorisedImage cImage = new SmutDetectCategorisedImage(bw, bh);
                cImage.setHits(rgbHits, yccHits);
                cImage.computePercentages(true, true);
                
                if (detectNudity) {
                    cImage.setNudity(classifyNudity(img, bw, bh));
                }
                return cImage;

            } finally {
                reader.dispose();
            }

        } catch (Exception | OutOfMemoryError e) {
            logger_.log(Level.WARNING, "Error scanning image for Skintone Analysis: "
                    + file.getName() + " (id=" + file.getId() + ")", e);
            return null;
        }
    }

    /**
     * Reads pixels straight from the raster when its layout is one we know is
     * identical to what getRGB would return. Anything else (indexed, gray,
     * 4BYTE_ABGR, custom colour spaces, premultiplied alpha, child rasters ...)
     * returns false so the caller uses getRGB.
     */
    private static boolean countFromRaster(BufferedImage img, int w, int h, long[] hits) {
        final WritableRaster raster = img.getRaster();
        if (raster.getParent() != null
                || raster.getSampleModelTranslateX() != 0
                || raster.getSampleModelTranslateY() != 0) {
            return false;
        }
        final int type = img.getType();
        final DataBuffer db = raster.getDataBuffer();
        final SampleModel sm = raster.getSampleModel();

        if ((type == BufferedImage.TYPE_INT_RGB || type == BufferedImage.TYPE_INT_ARGB)
                && db instanceof DataBufferInt
                && sm instanceof SinglePixelPackedSampleModel) {
            final int[] data = ((DataBufferInt) db).getData();
            final int n = w * h;
            if (db.getOffset() == 0
                    && ((SinglePixelPackedSampleModel) sm).getScanlineStride() == w
                    && data.length >= n) {
                SkinToneCounter.countPacked(data, 0, n, hits);
                return true;
            }
        } else if (type == BufferedImage.TYPE_3BYTE_BGR
                && db instanceof DataBufferByte
                && sm instanceof PixelInterleavedSampleModel) {
            final PixelInterleavedSampleModel pm = (PixelInterleavedSampleModel) sm;
            final int[] bands = pm.getBandOffsets(); // R, G, B offsets
            final byte[] data = ((DataBufferByte) db).getData();
            final int n = 3 * w * h;
            if (db.getOffset() == 0
                    && pm.getPixelStride() == 3
                    && pm.getScanlineStride() == 3 * w
                    && bands.length == 3 && bands[0] == 2 && bands[1] == 1 && bands[2] == 0
                    && data.length >= n) {
                SkinToneCounter.countBgr(data, 0, n, hits);
                return true;
            }
        }
        return false;
    }

}
