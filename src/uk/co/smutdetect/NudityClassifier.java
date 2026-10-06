package uk.co.smutdetect;

import java.util.Arrays;

/** Region-based nudity heuristic, ported from Riganopt. */
final class NudityClassifier {

    enum Result { NUDE, NOT_NUDE, NO_REGIONS, ERROR }

    private static final float H_MAX = 50f / 360f;
    private static final float S_MIN = 0.23f, S_MAX = 0.68f, V_MIN = 0.35f;

    private NudityClassifier() { }

    static boolean[] skinMask(int[] argb, int n) {
        boolean[] mask = new boolean[n];
        for (int i = 0; i < n; i++) {
            int p = argb[i];
            float r = ((p >> 16) & 0xFF) / 255f;
            float g = ((p >> 8) & 0xFF) / 255f;
            float b = (p & 0xFF) / 255f;
            float mx = Math.max(r, Math.max(g, b));
            float mn = Math.min(r, Math.min(g, b));
            float diff = mx - mn;
            float h;
            if (diff == 0)       h = 0f;
            else if (mx == r)  { h = (g - b) / diff; h -= 6f * (float) Math.floor(h / 6f); }
            else if (mx == g)    h = (b - r) / diff + 2f;
            else                 h = (r - g) / diff + 4f;
            h /= 6f;
            float s = (mx == 0) ? 0f : diff / mx;
            mask[i] = h <= H_MAX && s >= S_MIN && s <= S_MAX && mx >= V_MIN;
        }
        return mask;
    }

    static Result classify(int[] argb, int width, int height) {
        final int total = width * height;
        if (total <= 0 || argb.length < total) return Result.ERROR;

        boolean[] mask = skinMask(argb, total);
        int totalSkin = 0;
        for (boolean m : mask) if (m) totalSkin++;
        if (100.0 * totalSkin / total < 15) return Result.NOT_NUDE;

        int[] labels = new int[total];
        int[] stack = new int[total];
        int[] sizes = new int[64];
        int numRegions = 0;

        for (int start = 0; start < total; start++) {
            if (!mask[start] || labels[start] != 0) continue;
            numRegions++;
            int sp = 0, count = 0;
            stack[sp++] = start;
            labels[start] = numRegions;
            while (sp > 0) {
                int p = stack[--sp];
                count++;
                int x = p % width, y = p / width, q;
                if (x > 0)          { q = p - 1;     if (mask[q] && labels[q] == 0) { labels[q] = numRegions; stack[sp++] = q; } }
                if (x < width - 1)  { q = p + 1;     if (mask[q] && labels[q] == 0) { labels[q] = numRegions; stack[sp++] = q; } }
                if (y > 0)          { q = p - width; if (mask[q] && labels[q] == 0) { labels[q] = numRegions; stack[sp++] = q; } }
                if (y < height - 1) { q = p + width; if (mask[q] && labels[q] == 0) { labels[q] = numRegions; stack[sp++] = q; } }
            }
            if (numRegions > sizes.length) sizes = Arrays.copyOf(sizes, sizes.length * 2);
            sizes[numRegions - 1] = count;
        }
        if (numRegions == 0) return Result.NO_REGIONS;

        int largestLabel = 1;
        for (int i = 1; i < numRegions; i++) {
            if (sizes[i] > sizes[largestLabel - 1]) largestLabel = i + 1;
        }
        int[] sorted = Arrays.copyOf(sizes, numRegions);
        Arrays.sort(sorted);
        int largest = sorted[numRegions - 1];
        int second = numRegions > 1 ? sorted[numRegions - 2] : 0;
        int third  = numRegions > 2 ? sorted[numRegions - 3] : 0;

        int yMin = Integer.MAX_VALUE, xMin = Integer.MAX_VALUE, yMax = -1, xMax = -1;
        long channelSum = 0;
        for (int i = 0; i < total; i++) {
            if (labels[i] != largestLabel) continue;
            int x = i % width, y = i / width;
            if (x < xMin) xMin = x;
            if (x > xMax) xMax = x;
            if (y < yMin) yMin = y;
            if (y > yMax) yMax = y;
            int p = argb[i];
            channelSum += ((p >> 16) & 0xFF) + ((p >> 8) & 0xFF) + (p & 0xFF);
        }
        long polygonArea = (long) (xMax - xMin) * (yMax - yMin);
        double avgIntensity = channelSum / (3.0 * largest) / 255.0;

        if (largest < 0.35 * totalSkin && second < 0.3 * totalSkin && third < 0.3 * totalSkin) return Result.NOT_NUDE;
        if (largest < 0.45 * totalSkin) return Result.NOT_NUDE;
        if (totalSkin < 0.3 * total && largest < 0.55 * polygonArea) return Result.NOT_NUDE;
        if (numRegions > 60 && avgIntensity < 0.25) return Result.NOT_NUDE;
        return Result.NUDE;
    }
}