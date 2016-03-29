# Awesome Forensics

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome forensic analysis tools and resources. Inspired by
[awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis).


- [Awesome Forensics](#awesome-forensics)
- [Tools](#tools)
    - [Distributions](#distributions)
    - [Frameworks](#frameworks)
    - [Live forensics](#live-forensics)
    - [Carving](#carving)
    - [Memory Forensics](#memory-forensics)
    - [Network Forensics](#network-forensics)
    - [Windows Artifacts](#windows-artifacts)
    - [OS X Forensics](#os-x-forensics)
    - [Information Retrival](#information-retrival)
    - [Reverse Engineering](#reverse-engineering)
- [Learn Forensics](#learn-forensics)
    - [CTFs](#ctfs)
- [Resources](#resources)
    - [File System Corpora](#file-system-corpora)
    - [Twitter](#twitter)
    - [Other](#other)
- [Related Awesome Lists](#related-awesome-lists)
- [Contributing](#contributing)

---

# Tools

## Distributions
* [deft](http://www.deftlinux.net/) - Linux distribution for forensic analysis

## Frameworks
* [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) - Tools for low level forensic analysis
* [dff](https://github.com/arxsys/dff) - Forensic framework

## Live forensics
* [mig](https://github.com/mozilla/mig) - Distributed & real time digital forensics at the speed of the cloud
* [grr](https://github.com/google/grr) - GRR Rapid Response: remote live forensics for incident response

## Carving
* [bstrings](https://github.com/EricZimmerman/bstrings) - Improved strings utility
* [photorec](http://www.cgsecurity.org/wiki/PhotoRec) - File carving tool
* [see Maleware Analysis List](https://github.com/rshipp/awesome-malware-analysis#file-carving)

## Memory Forensics
* [MASCHE](https://github.com/mozilla/masche) - MIG Memory Forensic library
* [KeeFarce](https://github.com/denandz/KeeFarce) - Extract KeePass passwords from memory
* [see Maleware Analysis List](https://github.com/rshipp/awesome-malware-analysis#memory-forensics)

## Network Forensics
* [Wireshark](https://www.wireshark.org/) - The network traffic analysis tool

## Windows Artifacts
* [MFT-Parsers](http://az4n6.blogspot.de/2015/09/whos-your-master-mft-parsers-reviewed.html) - Comparison of MFT-Parsers
* [MFTExtractor](https://github.com/aarsakian/MFTExtractor) - MFT-Parser
* [python-ntfs](https://github.com/williballenthin/python-ntfs) - NTFS analysis
* [NTFS journal parser](http://strozfriedberg.github.io/ntfs-linker/)
* [NTFS USN Journal parser](https://github.com/PoorBillionaire/USN-Journal-Parser)
* [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - Collect artifacts on windows
* [see Maleware Analysis List](https://github.com/rshipp/awesome-malware-analysis#windows-artifacts)

## OS X Forensics
* [OSXAuditor](https://github.com/jipegit/OSXAuditor)

## Information Retrival
* [Turbinia](https://github.com/google/turbinia) - Experimental distributed/parallel forensic processing

## Reverse Engineering
* [Radare2](https://github.com/radare/radare2) - Reverse engineering framework
* [hachoir](https://bitbucket.org/blinkingtwelve/hachoir-cow/) - Framework for file manipulation

## File Grammars
* [WinHex Templates](https://www.x-ways.net/winhex/templates/) - Grammars for the WinHex editor and X-Ways
* [Synalyse It! Grammars](https://www.synalysis.net/formats.xml) - File type grammars for the Synalyze It! editor
* [HFSPlus Grammars](https://github.com/mac4n6/HFSPlus_Resources/tree/master/HFSPlus_Grammars) - HFS+ grammars for Synalysis
* [Contruct formats](https://github.com/construct/construct/tree/master/construct/formats) - Parser for different file formats for the python construct package
* [010 Editor Templates](http://www.sweetscape.com/010editor/templates/) - Templates for the 010 Editor
* [Sleuth Kit file system grammars](https://github.com/sleuthkit/sleuthkit/tree/develop/tsk/fs) - Grammars for different file systems
* [TestDisk grammars](https://github.com/cgsecurity/testdisk/tree/master/src) - Grammars used by TestDisk and PhotoRec

# Learn forensics

* [Forensic Challanges](http://www.amanhardikar.com/mindmaps/ForensicChallenges.html) - Mindmap of Forensic Challanges

## CTFs
* [Forensics CTFs](https://github.com/apsdehal/awesome-ctf/blob/master/README.md#forensics)

# Resources

## File System Corpora
* [Digital Forensics Tool Testing Images](http://dftt.sourceforge.net/)
* [The CFReDS Project](http://www.cfreds.nist.gov/)
  * [Hacking Case (4.5 GB NTFS Image)](http://www.cfreds.nist.gov/Hacking_Case.html)
* [FAU Open Research Challenge Digital Forensics](https://openresearchchallenge.org/digitalForensics/appliedforensiccomputinggroup)

## Websites
* [Forensics tools on Wikipedia](https://en.wikipedia.org/wiki/List_of_digital_forensics_tools)
* [Free computer forensic tools](https://forensiccontrol.com/resources/free-software/) - Comprehensive list of free computer forensic tools

## Twitter
* [@4n6ist](https://twitter.com/4n6ist)
* [@4n6k](https://twitter.com/4n6k)
* [@505Forensics](https://twitter.com/505Forensics)
* [@aheadless](https://twitter.com/aheadless)
* [@AppleExaminer](https://twitter.com/AppleExaminer)
* [@blackbagtech](https://twitter.com/blackbagtech)
* [@carrier4n6](https://twitter.com/carrier4n6)
* [@CindyMurph](https://twitter.com/CindyMurph)
* [@forensikblog](https://twitter.com/forensikblog)
* [@HECFBlog](https://twitter.com/HECFBlog)
* [@Hexacorn](https://twitter.com/Hexacorn)
* [@hiddenillusion](https://twitter.com/hiddenillusion)
* [@iamevltwin](https://twitter.com/iamevltwin)
* [@jaredcatkinson](https://twitter.com/jaredcatkinson)
* [@maridegrazia](https://twitter.com/maridegrazia)
* [@sleuthkit](https://twitter.com/sleuthkit)
* [@williballenthin](https://twitter.com/williballenthin)
* [@XWaysGuide](https://twitter.com/XWaysGuide)

## Other
* [Reddit](https://www.reddit.com/r/computerforensics/)

# Related Awesome Lists

* [Android Security](https://github.com/ashishb/android-security-awesome)
* [AppSec](https://github.com/paragonie/awesome-appsec)
* [CTFs](https://github.com/apsdehal/awesome-ctf)
* ["Hacking"](https://github.com/carpedm20/awesome-hacking)
* [Honeypots](https://github.com/paralax/awesome-honeypots)
* [Incident-Response](https://github.com/meirwah/awesome-incident-response)
* [Infosec](https://github.com/onlurking/awesome-infosec)
* [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
* [PCAP Tools](https://github.com/caesar0301/awesome-pcaptools)
* [Pentesting](https://github.com/enaqx/awesome-pentest)
* [Security](https://github.com/sbilly/awesome-security)

# [Contributing](CONTRIBUTING.md)

Pull requests and issues with suggestions are welcome!


