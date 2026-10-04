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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.logging.Level;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.coreutils.ImageUtils;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.autopsy.ingest.IngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleReferenceCounter;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.AnalysisResultAdded;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Score;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData;
import uk.co.smutdetect.SmutDetectCategorisedImage;
import uk.co.smutdetect.SmutDetectImageScanner;

/**
 * File ingest module that scans images for skin-tone pixels and tags each
 * scanned image with its skin-tone percentage (in steps of 10).
 *
 * @author Rajmund Witt <code@4ensics.co.uk>
 */
class SmutDetectFileIngestModule implements FileIngestModule {

    // Shared between module instances; access only via the synchronized
    // static methods below.
    private static final HashMap<Long, Long> artifactCountsForIngestJobs = new HashMap<>();
    private static final IngestModuleReferenceCounter refCounter = new IngestModuleReferenceCounter();
    private static final String MODULE_NAME = SmutDetectIngestModuleFactory.getModuleName();

    /** Enough bytes for the longest signature checked (JPEG 2000: 8). */
    private static final int HEADER_BYTES = 12;

    // Per-instance, per-job settings (these must NOT be static: several ingest
    // jobs with different settings can run at the same time).
    private final boolean skipKnownFiles;
    private final boolean useThumbnail;
    private final long minSize;

    private IngestJobContext context = null;
    private Blackboard blackboard = null;

    SmutDetectFileIngestModule(SmutDetectIngestJobSettings settings) {
        this.skipKnownFiles = settings.skipKnownFiles();
        this.useThumbnail = settings.useThumbnail();
        this.minSize = settings.minSizeFiles();
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;
        try {
            blackboard = Case.getCurrentCaseThrows().getSleuthkitCase().getBlackboard();
        } catch (NoCurrentCaseException ex) {
            throw new IngestModuleException("No case is open", ex);
        }
        refCounter.incrementAndGet(context.getJobId());
    }

    @Override
    public IngestModule.ProcessResult process(AbstractFile file) {
        // Skip anything other than actual file system files.
        if (file.isDir()
                || file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS
                || file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) {
            return IngestModule.ProcessResult.OK;
        }

        // Skip NSRL / known files, if the config allows it.
        if (skipKnownFiles && file.getKnown() == TskData.FileKnown.KNOWN) {
            return IngestModule.ProcessResult.OK;
        }

        // Skip unsupported formats.
        if (!isImageFile(file)) {
            return IngestModule.ProcessResult.OK;
        }

        try {
            SmutDetectCategorisedImage cImage = SmutDetectImageScanner.scanImage(file);
            if (cImage == null) {
                return IngestModule.ProcessResult.OK; // not decodable; logged by the scanner
            }

            // Round down to a multiple of 10 (integer division floors).
            int roundedPercentage = (cImage.getReadableAveragePercentage() / 10) * 10;

            Collection<BlackboardAttribute> attributes = new ArrayList<>();
            attributes.add(new BlackboardAttribute(
                    new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT),
                    MODULE_NAME, cImage.toString()));
            attributes.add(new BlackboardAttribute(
                    new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME),
                    MODULE_NAME, "SmutDetect|" + String.format("%03d", roundedPercentage) + "s"));

            // This overload uses the file's own data source.
            AnalysisResultAdded resultAdded = file.newAnalysisResult(
                    BlackboardArtifact.Type.TSK_INTERESTING_ITEM,
                    Score.SCORE_UNKNOWN,
                    null,        // conclusion
                    null,        // configuration
                    null,        // justification
                    attributes);

            // Creating the result only writes it to the case database; posting
            // it notifies the UI and other modules. (Newer Autopsy versions
            // also offer postArtifact(artifact, moduleName, context.getJobId()).)
            blackboard.postArtifact(resultAdded.getAnalysisResult(), MODULE_NAME);

            addToBlackboardPostCount(context.getJobId(), 1L);
            return IngestModule.ProcessResult.OK;

        } catch (TskCoreException | Blackboard.BlackboardException ex) {
            Logger logger = IngestServices.getInstance().getLogger(MODULE_NAME);
            logger.log(Level.SEVERE, "Error processing file (id = " + file.getId() + ")", ex);
            return IngestModule.ProcessResult.ERROR;
        }
    }

    @Override
    public void shutDown() {
        if (context != null) {
            // Always decrement the reference count (even if cancelled) so the
            // per-job entry is released; only post the summary if not cancelled.
            reportBlackboardPostCount(context.getJobId(), !context.fileIngestIsCancelled());
        }
    }

    synchronized static void addToBlackboardPostCount(long ingestJobId, long countToAdd) {
        Long fileCount = artifactCountsForIngestJobs.get(ingestJobId);
        if (fileCount == null) {
            fileCount = 0L;
        }
        artifactCountsForIngestJobs.put(ingestJobId, fileCount + countToAdd);
    }

    synchronized static void reportBlackboardPostCount(long ingestJobId, boolean postMessage) {
        Long refCount = refCounter.decrementAndGet(ingestJobId);
        if (refCount == 0) {
            Long filesCount = artifactCountsForIngestJobs.remove(ingestJobId);
            if (postMessage) {
                String msgText = String.format("Posted %d times to the blackboard",
                        filesCount == null ? 0L : filesCount);
                IngestServices.getInstance().postMessage(IngestMessage.createMessage(
                        IngestMessage.MessageType.INFO, MODULE_NAME, msgText));
            }
        }
    }

    /**
     * Decides whether to attempt a skin-tone scan of the file: it must be at
     * least minSize bytes and either be thumbnail-capable (if enabled in the
     * settings) or start with a known image signature.
     *
     * @param file file to be checked
     * @return true if the file should be scanned
     */
    private boolean isImageFile(AbstractFile file) {
        if (file.getSize() < minSize) {
            return false;
        }

        if (useThumbnail && ImageUtils.isImageThumbnailSupported(file)) {
            return true;
        }

        byte[] header = new byte[HEADER_BYTES];
        int bytesRead;
        try {
            bytesRead = file.read(header, 0, HEADER_BYTES);
        } catch (TskCoreException ex) {
            return false; // can't read the first few bytes: don't parse
        }
        if (bytesRead <= 0) {
            return false;
        }

        // Signatures, most likely first. See
        // http://www.garykessler.net/library/file_sigs.html
        return startsWith(header, bytesRead, 0xFF, 0xD8, 0xFF)                              // JPEG
                || startsWith(header, bytesRead, 0x42, 0x4D)                                // BMP "BM"
                || startsWith(header, bytesRead, 0x89, 0x50, 0x4E, 0x47)                    // PNG (rest not checked)
                || startsWith(header, bytesRead, 0x47, 0x49, 0x46, 0x38)                    // GIF87a / GIF89a
                || startsWith(header, bytesRead, 0x49, 0x20, 0x49)                          // TIFF "I I"
                || startsWith(header, bytesRead, 0x49, 0x49, 0x2A, 0x00)                    // TIFF little endian
                || startsWith(header, bytesRead, 0x4D, 0x4D, 0x00, 0x2A)                    // TIFF big endian
                || startsWith(header, bytesRead, 0x4D, 0x4D, 0x00, 0x2B)                    // BigTIFF
                || startsWith(header, bytesRead, 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20); // JPEG 2000 (JP2)
    }

    /** @return true if the first sig.length bytes read match the signature */
    private static boolean startsWith(byte[] buf, int bytesRead, int... sig) {
        if (bytesRead < sig.length) {
            return false;
        }
        for (int i = 0; i < sig.length; i++) {
            if ((buf[i] & 0xFF) != sig[i]) {
                return false;
            }
        }
        return true;
    }
}
