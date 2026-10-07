/**
 * SmutDetect4Autopsy
 * Copyright (C) 2014 Rajmund Witt
 * 
 * Derived from Sample Module provided with Autopsy 3.1.
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
 * 
 */
package uk.co.smutdetect.autopsy;

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

/**
 * Ingest job options for the SmutDetect ingest module.
 */
public class SmutDetectIngestJobSettings implements IngestModuleIngestJobSettings {

    // Bumped from 1 when minSize was added: settings saved by the old class
    // would otherwise deserialise with minSize == 0 (field initialisers do not
    // run on deserialisation). Autopsy falls back to the defaults instead.
    private static final long serialVersionUID = 1L;

    private boolean skipKnownFiles = true;
    private boolean useThumbnail = true;
    private long minSize = 100;
    private boolean detectNudity = true;

    SmutDetectIngestJobSettings() {
    }

    SmutDetectIngestJobSettings(boolean skipKnownFiles, boolean useThumbnail, long minSize) {
        this.skipKnownFiles = skipKnownFiles;
        this.useThumbnail = useThumbnail;
        this.minSize = minSize;
    }

    @Override
    public long getVersionNumber() {
        return serialVersionUID;
    }

    void setSkipKnownFiles(boolean enabled) {
        skipKnownFiles = enabled;
    }

    void setUseThumbnail(boolean enabled) {
        useThumbnail = enabled;
    }

    void setMinSize(long minSize) {
        this.minSize = minSize;
    }

    boolean skipKnownFiles() {
        return skipKnownFiles;
    }

    boolean useThumbnail() {
        return useThumbnail;
    }

    long minSizeFiles() {
        return minSize;
    }
}
