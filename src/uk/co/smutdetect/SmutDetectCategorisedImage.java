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
 * Container for the skin-tone statistics of one scanned image.
 *
 * All percentage maths is done with integer arithmetic, so there is no
 * floating-point truncation (e.g. 29 of 100 pixels is 29%, not 28%) and no
 * int overflow on large images.
 *
 * @author Rajmund Witt
 * @version 0.6
 */
public class SmutDetectCategorisedImage {

    private static final int MAX_DIMENSION = 100000;

    private final int width_;
    private final int height_;
    private final long numberOfPixels_;

    private boolean hasSkinTone_;
    private boolean isProcessedCorrectly_;
    private long numberOfRgbSkinToneHits_;
    private long numberOfYCbCrSkinToneHits_;
    private double preciseRgbPercentage_;
    private double preciseYCbCrPercentage_;
    private double preciseAveragePercentage_;
    private int readableRgbPercentage_;
    private int readableYCbCrPercentage_;
    private int readableAveragePercentage_;

    /**
     * @param width  width in pixels of the image as scanned
     * @param height height in pixels of the image as scanned
     *
     * Implausible dimensions leave the image flagged as not processed
     * correctly, which makes computePercentages() report 100% so the file is
     * listed for manual review.
     */
    public SmutDetectCategorisedImage(int width, int height) {
        if (width > 0 && width < MAX_DIMENSION && height > 0 && height < MAX_DIMENSION) {
            width_ = width;
            height_ = height;
            numberOfPixels_ = (long) width * height;
            isProcessedCorrectly_ = true;
        } else {
            width_ = 0;
            height_ = 0;
            numberOfPixels_ = 0;
            isProcessedCorrectly_ = false;
        }
    }

    // ------------------------------- getters ---------------------------------

    public int getWidth() { return width_; }
    public int getHeight() { return height_; }
    public boolean getHasSkinTone() { return hasSkinTone_; }
    public boolean getIsProcessedCorrectly() { return isProcessedCorrectly_; }
    public long getNumberOfPixels() { return numberOfPixels_; }
    public double getPreciseRgbPercentage() { return preciseRgbPercentage_; }
    public double getPreciseYCbCrPercentage() { return preciseYCbCrPercentage_; }
    public double getPreciseAveragePercentage() { return preciseAveragePercentage_; }
    public int getReadableRgbPercentage() { return readableRgbPercentage_; }
    public int getReadableYCbCrPercentage() { return readableYCbCrPercentage_; }
    public int getReadableAveragePercentage() { return readableAveragePercentage_; }

    // ------------------------------- setters ---------------------------------

    public void setHasSkinTone(boolean hasSkinTone) {
        hasSkinTone_ = hasSkinTone;
    }

    /**
     * Sets the total hit counts for the whole image. Replaces the old
     * per-pixel increment methods.
     */
    public void setHits(long rgbHits, long yCbCrHits) {
        numberOfRgbSkinToneHits_ = rgbHits;
        numberOfYCbCrSkinToneHits_ = yCbCrHits;
    }

    // ------------------------------- compute ---------------------------------

    /**
     * Computes the percentages. Call once, after the whole image has been
     * scanned and setHits() has been called.
     *
     * @param usedRGB    the RGB test contributes to the average
     * @param usedYCbCr  the YCbCr test contributes to the average
     */
    public void computePercentages(boolean usedRGB, boolean usedYCbCr) {
        final long px = numberOfPixels_;

        if (!isProcessedCorrectly_ || px <= 0
                || numberOfRgbSkinToneHits_ < 0 || numberOfRgbSkinToneHits_ > px
                || numberOfYCbCrSkinToneHits_ < 0 || numberOfYCbCrSkinToneHits_ > px) {
            // Something is illogical: force 100% so the image gets listed and
            // checked manually.
            isProcessedCorrectly_ = false;
            preciseRgbPercentage_ = 1.0;
            preciseYCbCrPercentage_ = 1.0;
            preciseAveragePercentage_ = 1.0;
            readableRgbPercentage_ = 100;
            readableYCbCrPercentage_ = 100;
            readableAveragePercentage_ = 100;
            return;
        }

        final long rgb = numberOfRgbSkinToneHits_;
        final long ycc = numberOfYCbCrSkinToneHits_;

        hasSkinTone_ = rgb > 0 || ycc > 0;

        preciseRgbPercentage_ = (double) rgb / px;
        preciseYCbCrPercentage_ = (double) ycc / px;
        readableRgbPercentage_ = (int) (rgb * 100L / px);
        readableYCbCrPercentage_ = (int) (ycc * 100L / px);

        if (usedRGB && usedYCbCr) {
            preciseAveragePercentage_ = (preciseRgbPercentage_ + preciseYCbCrPercentage_) / 2.0;
            readableAveragePercentage_ = (int) ((rgb + ycc) * 50L / px);
        } else if (usedYCbCr) {
            preciseAveragePercentage_ = preciseYCbCrPercentage_;
            readableAveragePercentage_ = readableYCbCrPercentage_;
        } else {
            preciseAveragePercentage_ = preciseRgbPercentage_;
            readableAveragePercentage_ = readableRgbPercentage_;
        }
    }

    /** @return textual representation, used as the artifact comment */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append(readableAveragePercentage_).append("%\n");
        s.append(width_).append("x").append(height_).append(" = ").append(numberOfPixels_).append("px\n");
        s.append("RGB DetectorValue: ").append(preciseRgbPercentage_);
        s.append("\nYCbCr DetectorValue: ").append(preciseYCbCrPercentage_);
        s.append("\nProcessed correctly: ").append(isProcessedCorrectly_);
        return s.toString();
    }
}
