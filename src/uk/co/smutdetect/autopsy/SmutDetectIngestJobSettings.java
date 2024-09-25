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

import javax.swing.JTextField;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

/**
 * Ingest job options for sample ingest module instances.
 */
public class SmutDetectIngestJobSettings implements IngestModuleIngestJobSettings {
    
    private static final long serialVersionUID = 1L;
    private boolean skipKnownFiles = true;
    private boolean useThumbnail = true;
    private int minSize = 100;

    SmutDetectIngestJobSettings() {
    }

    SmutDetectIngestJobSettings(boolean skipKnownFiles, boolean useThumbnail, int minSize) {
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
    
    void setuseHeaders(boolean disabled) {
        useThumbnail = disabled;
    }

    boolean skipKnownFiles() {
        return skipKnownFiles;
    }
    
    boolean useThumbnail() {
        return useThumbnail;
    }
    
    int minSizeFiles() {
        return minSize;
    }
}