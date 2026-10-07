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

/**
 * Branchless, allocation-free skin-tone counting kernels.
 *
 * The per-pixel tests are written with integer arithmetic and sign-bit tricks
 * (no short-circuit branches, no floating point) so the JIT can unroll and
 * auto-vectorise the loops, and so run time does not depend on image content.
 *
 * They are exactly equivalent to {@link RgbSkinToneDetector#checkColor(int)}
 * and {@link YCbCrSkinToneDetector#checkColor(int)}, which remain the reference
 * implementations (verified over all 2^24 colours):
 *
 * RGB:   R>95, G>40, B>20, R>B, R-G>15
 *
 * YCbCr: the original tests cb = (int)(-0.1687R - 0.3313G + 0.5B + 128) in
 *        [77,127] and cr = (int)(0.5R - 0.4187G - 0.0813B + 128) in [133,173].
 *        The sums are never negative, so (int) is floor. Scaling the
 *        coefficients by 10000 makes them exact integers, and
 *        floor(N/10000) in [lo,hi] is the same as N in [lo*10000,
 *        (hi+1)*10000), so no division is needed.
 *
 * "a > b" is computed as ((b - a) >>> 31): the sign bit of b-a. All operands
 * are small, so b-a cannot overflow.
 */
final class SkinToneCounter {

    /** Pixels per inner loop; keeps the int accumulators far from overflow. */
    private static final int CHUNK = 1 << 16;

    private SkinToneCounter() {
    }

    /**
     * Counts hits in packed pixels (0xAARRGGBB or 0x00RRGGBB; alpha ignored).
     *
     * @param p    pixels
     * @param from first index
     * @param to   one past the last index
     * @param hits long[2]; the RGB hit count is added to [0], YCbCr to [1]
     */
    static void countPacked(int[] p, int from, int to, long[] hits) {
        long rgbTotal = 0;
        long yccTotal = 0;
        for (int s = from; s < to; s += CHUNK) {
            final int e = Math.min(to, s + CHUNK);
            int rgb = 0;
            int ycc = 0;
            for (int i = s; i < e; i++) {
                final int c = p[i];
                final int r = (c >> 16) & 0xFF;
                final int g = (c >> 8) & 0xFF;
                final int b = c & 0xFF;
                rgb += rgbHit(r, g, b);
                ycc += yccHit(r, g, b);
            }
            rgbTotal += rgb;
            yccTotal += ycc;
        }
        hits[0] += rgbTotal;
        hits[1] += yccTotal;
    }

    /**
     * Counts hits in interleaved B,G,R byte triplets (BufferedImage
     * TYPE_3BYTE_BGR raster data).
     *
     * @param d    data
     * @param from first byte index (multiple of 3 from the start of a pixel)
     * @param to   one past the last byte index; (to - from) must be a multiple of 3
     * @param hits long[2]; the RGB hit count is added to [0], YCbCr to [1]
     */
    static void countBgr(byte[] d, int from, int to, long[] hits) {
        long rgbTotal = 0;
        long yccTotal = 0;
        final int chunkBytes = CHUNK * 3;
        for (int s = from; s < to; s += chunkBytes) {
            final int e = Math.min(to, s + chunkBytes);
            int rgb = 0;
            int ycc = 0;
            for (int i = s; i < e; i += 3) {
                final int b = d[i] & 0xFF;
                final int g = d[i + 1] & 0xFF;
                final int r = d[i + 2] & 0xFF;
                rgb += rgbHit(r, g, b);
                ycc += yccHit(r, g, b);
            }
            rgbTotal += rgb;
            yccTotal += ycc;
        }
        hits[0] += rgbTotal;
        hits[1] += yccTotal;
    }

    /** @return 1 if skin by the RGB rule, else 0 */
    private static int rgbHit(int r, int g, int b) {
        return ((95 - r) >>> 31) & ((40 - g) >>> 31) & ((20 - b) >>> 31)
                & ((b - r) >>> 31) & ((15 - (r - g)) >>> 31);
    }

    /** @return 1 if skin by the YCbCr rule, else 0 */
    private static int yccHit(int r, int g, int b) {
        final int nb = -1687 * r - 3313 * g + 5000 * b + 1280000; // 10000 * (cb)
        final int nr = 5000 * r - 4187 * g - 813 * b + 1280000;   // 10000 * (cr)
        return (1 ^ ((nb - 770000) >>> 31))     // nb >= 77  * 10000
                & ((nb - 1280000) >>> 31)       // nb <  128 * 10000
                & (1 ^ ((nr - 1330000) >>> 31)) // nr >= 133 * 10000
                & ((nr - 1740000) >>> 31);      // nr <  174 * 10000
    }
}
