# SmutDetect4Autopsy

A skin-tone and nudity image detection ingest module for [Autopsy](https://www.autopsy.com/), the open-source digital forensics platform built on The Sleuth Kit. It helps investigators triage recovered or seized storage by flagging images that contain a high proportion of skin-tone pixels, or that are likely to contain nudity, so they can be reviewed first.

> This repository is a fork of [rajwitt/SmutDetect4Autopsy](https://github.com/rajwitt/SmutDetect4Autopsy), originally written by Rajmund Witt as a port of his standalone SmutDetect tool to an Autopsy module.

## Overview

Reviewing every image on a suspect device is slow. SmutDetect4Autopsy runs as part of Autopsy's ingest pipeline and uses two complementary detection approaches:

1. **Skin-tone detection:** scores image files by the percentage of pixels that fall within skin-tone ranges, using RGB and YCbCr colour-space heuristics based on the concept behind the FileHound forensic tool.
2. **Nudity detection:** applies the algorithm described in Rigan Ap-apid's paper *"An Algorithm for Nudity Detection"*, which goes beyond a raw skin-pixel percentage by analysing the skin regions found in the image to estimate whether it is likely to contain nudity.

Images that meet the configured criteria can be flagged and reviewed within the Autopsy interface.

**Important:** both methods are triage aids, not definitive classifiers. They will produce false positives (beaches, deserts, wood, portraits, close-ups, food) and false negatives (greyscale or heavily edited images). Results must always be reviewed by a trained examiner and must never be treated as evidence of content on their own.

## Features

- Skin-tone detection on image files using RGB and YCbCr colour-space algorithms
- Nudity detection using a Java implementation of Rigan Ap-apid's nudity detection algorithm
- Configurable skin-tone percentage threshold
- Runs as an Autopsy file ingest module on each data source added to a case
- Written in Java as a NetBeans / Autopsy platform module

## Requirements

- [Autopsy](https://www.autopsy.com/download/) (a version matching the one the module was built against)
- Java runtime bundled with that Autopsy release
- To build from source: [Apache NetBeans](https://netbeans.apache.org/) with the Autopsy platform configured, and Apache Ant

> **Version compatibility:** Autopsy modules are tied to the Java version and platform libraries of the Autopsy release they were compiled for. Older releases of this module were built for Autopsy 3.x. For current Autopsy releases (4.20 and later), you will need to rebuild the module against your installed Autopsy version, otherwise installation may fail with plugin validation errors (for example, `unpack200` or `Common Annotations` version errors).

## Installation

### From a pre-built `.nbm`

1. Open Autopsy and go to **Tools → Plugins**.
2. Select the **Downloaded** tab and click **Add Plugins…**.
3. Choose the `uk-co-smutdetect.nbm` file.
4. Click **Install** and follow the prompts. Autopsy may warn that the module signature is not trusted; this is expected for unsigned third-party modules.
5. Restart Autopsy if prompted.

### Building from source

1. Clone the repository:
   ```bash
   git clone https://github.com/TDClarke/SmutDetect4Autopsy.git
   ```
2. Open the project in NetBeans (the `nbproject/` directory contains the project configuration).
3. Make sure the project's platform is set to your installed Autopsy (or its NetBeans platform build).
4. Right-click the project and choose **Create NBM**.
5. Install the generated `.nbm` as described above.

## Usage

1. Create or open a case in Autopsy and add a data source.
2. In the **Configure Ingest** dialog, enable the **SmutDetect** module.
3. Adjust the module settings (such as the skin-tone threshold and which detection methods to use) if needed.
4. Run ingest and review flagged images in the results tree.

## Project structure

```
SmutDetect4Autopsy/
├── nbproject/                 NetBeans project configuration
├── src/uk/co/smutdetect/      Module source code
├── build.xml                  Ant build script
├── manifest.mf                Module manifest
└── .gitignore
```

## Contributing

Issues and pull requests are welcome, particularly updates for newer Autopsy and Java versions. Please open an issue to discuss larger changes first.

## Credits

- **Rajmund Witt**: original author of SmutDetect and SmutDetect4Autopsy
- Skin-tone detection concepts drawn from the documented approach of the FileHound tool
- **Rigan Ap-apid**: author of *"An Algorithm for Nudity Detection"*, on which the nudity detection is based. A standalone Java implementation is also available at [TDClarke/Rigan-Ap-apaid](https://github.com/TDClarke/Rigan-Ap-apaid)

## Links

- Original project: <https://github.com/rajwitt/SmutDetect4Autopsy>
- Original documentation: <http://www.smutdetect.co.uk>
- Autopsy third-party modules list: <https://github.com/sleuthkit/autopsy_addon_modules>

## License

Released under the **GNU General Public License v3.0**, as per the original project. See `LICENSE` for details. If the file is not present in this repository, add a copy of the GPLv3 text.

## Disclaimer

This software is provided for lawful digital forensic and investigative use. It is provided as-is without warranty, and its skin-tone and nudity detection output is an investigative lead rather than a determination of what an image contains.
