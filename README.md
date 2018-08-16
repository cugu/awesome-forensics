# Awesome Forensics [![Link Status](https://api.travis-ci.org/cugu/awesome-forensics.svg?branch=master)](https://travis-ci.org/cugu/awesome-forensics)

Curated list of awesome **free** (mostly open source) forensic analysis tools and resources.

- [Awesome Forensics](#awesome-forensics)
- [Collections](#collections)
- [Tools](#tools)
  - [Distributions](#distributions)
  - [Frameworks](#frameworks)
  - [Live forensics](#live-forensics)
  - [Imageing](#imageing)
  - [Carving](#carving)
  - [Memory Forensics](#memory-forensics)
  - [Network Forensics](#network-forensics)
  - [Windows Artifacts](#windows-artifacts)
  - [OS X Forensics](#os-x-forensics)
  - [Internet Artifacts](#internet-artifacts)
  - [Timeline Analysis](#timeline-analysis)
  - [Disk image handling](#disk-image-handling)
  - [Decryption](#decryption)
- [Learn Forensics](#learn-forensics)
  - [CTFs](#ctfs)
- [Resources](#resources)
  - [Books](#books)
  - [File System Corpora](#file-system-corpora)
  - [Twitter](#twitter)
  - [Blogs](#blogs)
  - [Other](#other)
- [Related Awesome Lists](#related-awesome-lists)
- [Contributing](#contributing)

---

## Collections

- [DFIR – The definitive compendium project](https://aboutdfir.com) - Collection of forensic resources for learning and research. Offers lists of certifications, books, blogs, challenges and more
- [dfir.training](https://www.dfir.training/) - Database of forensic resources focused on events, tools and more
- [ForensicArtifacts.com Artifact Repository](https://github.com/ForensicArtifacts/artifacts) - Machine-readable knowledge base of forensic artifacts

## Tools

- [Forensics tools on Wikipedia](https://en.wikipedia.org/wiki/List_of_digital_forensics_tools)
- [Free computer forensic tools](https://forensiccontrol.com/resources/free-software/) - Comprehensive list of free computer forensic tools

### Distributions

- [bitscout](https://github.com/vitaly-kamluk/bitscout) - LiveCD/LiveUSB for remote forensic acquisition and analysis
- [deft](http://www.deftlinux.net) - Linux distribution for forensic analysis
- [SANS Investigative Forensics Toolkit (sift)](https://github.com/sans-dfir/sift) - Linux distribution for forensic analysis

### Frameworks

- [dff](https://github.com/arxsys/dff) - Forensic framework
- [IntelMQ](https://github.com/certtools/intelmq) - IntelMQ collects and processes security feeds
- [Laika BOSS](https://github.com/lmco/laikaboss) - Laika is an object scanner and intrusion detection system
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - PowerForensics is a framework for live disk forensic analysis
- [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) - Tools for low level forensic analysis
- [turbinia](https://github.com/google/turbinia) - Turbinia is an open-source framework for deploying, managing, and running forensic workloads on cloud platforms

### Live forensics

- [grr](https://github.com/google/grr) - GRR Rapid Response: remote live forensics for incident response
- [Linux Expl0rer](https://github.com/intezer/linux-explorer) - Easy-to-use live forensics toolbox for Linux endpoints written in Python & Flask
- [mig](https://github.com/mozilla/mig) - Distributed & real time digital forensics at the speed of the cloud
- [osquery](https://github.com/facebook/osquery) - SQL powered operating system analytics

### Imageing

- [dc3dd](https://sourceforge.net/projects/dc3dd/) - Improved version of dd
- [dcfldd](http://dcfldd.sourceforge.net) - Different improved version of dd (this version has some bugs!, another version is on github [adulau/dcfldd](https://github.com/adulau/dcfldd))
- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-3.4.3/) - Free imageing tool for windows
- [Guymager](http://guymager.sourceforge.net) - Open source version for disk imageing on linux systems

### Carving

*more at [Malware Analysis List](https://github.com/rshipp/awesome-malware-analysis#file-carving)*

- [bstrings](https://github.com/EricZimmerman/bstrings) - Improved strings utility
- [bulk_extractor](https://github.com/simsong/bulk_extractor) - Extracts informations like email adresses, creditscard numbers and histrograms of disk images
- [floss](https://github.com/fireeye/flare-floss) - Static analysis tool to automatically deobfuscate strings from malware binaries
- [photorec](https://www.cgsecurity.org/wiki/PhotoRec) - File carving tool
- [swap_digger](https://github.com/sevagas/swap_digger) - A bash script used to automate Linux swap analysis, automating swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, etc.

### Memory Forensics

*more at [Malware Analysis List](https://github.com/rshipp/awesome-malware-analysis#memory-forensics)*

- [inVtero.net](https://github.com/ShaneK2/inVtero.net) - High speed memory analysis framework
  developed in .NET supports all Windows x64, includes code integrity and write support.
- [KeeFarce](https://github.com/denandz/KeeFarce) - Extract KeePass passwords from memory
- [Rekall](https://github.com/google/rekall) - Memory Forensic Framework
- [volatility](https://github.com/volatilityfoundation/volatility) - The memory forensic framework
- [VolUtility](https://github.com/kevthehermit/VolUtility) - Web App for Volatility framework

### Network Forensics

*more at [Malware Analysis List](https://github.com/rshipp/awesome-malware-analysis#network), [Forensicswiki's Tool List](http://forensicswiki.org/wiki/Tools:Network_Forensics), [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools) and [Wireshark Tool and Script List](https://wiki.wireshark.org/Tools)*

- [SiLK Tools](https://tools.netsa.cert.org/silk/) - SiLK is a suite of network traffic collection and analysis tools
- [Wireshark](https://www.wireshark.org) - The network traffic analysis tool
- [NetLytics](https://github.com/marty90/netlytics/) - Analytics platform to process network data on Spark.

### Windows Artifacts

*more at [Malware Analysis List](https://github.com/rshipp/awesome-malware-analysis#windows-artifacts)*

- [ArtifactExtractor](https://github.com/Silv3rHorn/ArtifactExtractor) - Extract common Windows artifacts from source images and VSCs
- [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - Collect artifacts on windows
- [FRED](https://www.pinguin.lu/fred) - Cross-platform microsoft registry hive editor
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Investigate malicious Windows logon by visualizing and analyzing Windows event log
- [MFT-Parsers](http://az4n6.blogspot.com/2015/09/whos-your-master-mft-parsers-reviewed.html) - Comparison of MFT-Parsers
- [MFTExtractor](https://github.com/aarsakian/MFTExtractor) - MFT-Parser
- [NTFS journal parser](http://strozfriedberg.github.io/ntfs-linker/)
- [NTFS USN Journal parser](https://github.com/PoorBillionaire/USN-Journal-Parser)
- [RecuperaBit](https://github.com/Lazza/RecuperaBit) - Reconstruct and recover NTFS data
- [python-ntfs](https://github.com/williballenthin/python-ntfs) - NTFS analysis

### OS X Forensics

- [OSXAuditor](https://github.com/jipegit/OSXAuditor)
- [OSX Collect](https://github.com/Yelp/osxcollector)

### Internet Artifacts

- [chrome-url-dumper](https://github.com/eLoopWoo/chrome-url-dumper) - Dump all local stored infromation collected by Chrome
- [hindsight](https://github.com/obsidianforensics/hindsight) - Internet history forensics for Google Chrome/Chromium

### Timeline Analysis

- [DFTimewolf](https://github.com/log2timeline/dftimewolf) - Framework for orchestrating forensic collection, processing and data export using GRR and Rekall
- [plaso](https://github.com/log2timeline/plaso) - Extract timestamps from various files and aggregate them
- [timesketch](https://github.com/google/timesketch) - Collaborative forensic timeline analysis

### Disk image handling

- [aff4](https://github.com/google/aff4) - AFF4 is an alternative, fast file format
- [Disk Arbitrator](https://github.com/aburgh/Disk-Arbitrator) - A Mac OS X forensic utility designed to help the user ensure correct forensic procedures are followed during imaging of a disk device
- [docker-explorer](https://github.com/google/docker-explorer/) - A tool to help forensicate offline docker acquisitions
- [imagemounter](https://github.com/ralphje/imagemounter) - Command line utility and Python package to ease the (un)mounting of forensic disk images
- [libewf](https://github.com/libyal/libewf) - Libewf is a library and some tools to access the Expert Witness Compression Format (EWF, E01)
- [xmount](https://www.pinguin.lu/xmount) - Convert between different disk image formats

### Decryption

- [hashcat](https://hashcat.net/hashcat/) - Fast password cracker with GPU support
- [John the Ripper](http://www.openwall.com/john/) - Password cracker

## Learn forensics

- [Forensic challanges](http://www.amanhardikar.com/mindmaps/ForensicChallenges.html) - Mindmap of forensic challanges
- [Training material](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational) - Online training material by European Union Agency for Network and Information Security for different topics (e.g. [Digital forensics](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#digital_forensics), [Network forensics](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#network_forensics))

### CTFs

- [Forensics CTFs](https://github.com/apsdehal/awesome-ctf/blob/master/README.md#forensics)
- [Precision Widgets of North Dakota Intrusion
](https://betweentwodfirns.blogspot.com/2017/11/dfir-ctf-precision-widgets-of-north.html)

## Resources

### Books

*more at [Recommended Readings](http://dfir.org/?q=node/8) by Andrew Case*

- [Network Forensics: Tracking Hackers through Cyberspace](https://www.pearson.com/us/higher-education/program/Davidoff-Network-Forensics-Tracking-Hackers-through-Cyberspace/PGM322390.html) - Learn to recognize hackers’ tracks and uncover network-based evidence
- [The Art of Memory Forensics](https://www.memoryanalysis.net/amf) - Detecting Malware and Threats in Windows, Linux, and Mac Memory
- [The Practice of Network Security Monitoring](https://nostarch.com/nsm) - Understanding Incident Detection and Response

### File System Corpora

- [Digital Forensic Challenge Images](https://www.ashemery.com/dfir.html) - Two DFIR challanges with images
- [Digital Forensics Tool Testing Images](http://dftt.sourceforge.net)
- [FAU Open Research Challenge Digital Forensics](https://openresearchchallenge.org/digitalForensics/appliedforensiccomputinggroup)
- [The CFReDS Project](https://www.cfreds.nist.gov)
  - [Hacking Case (4.5 GB NTFS Image)](https://www.cfreds.nist.gov/Hacking_Case.html)

### Twitter

- [@4n6ist](https://twitter.com/4n6ist)
- [@4n6k](https://twitter.com/4n6k)
- [@aheadless](https://twitter.com/aheadless)
- [@AppleExaminer](https://twitter.com/AppleExaminer) - Apple OS X & iOS Digital Forensics
- [@blackbagtech](https://twitter.com/blackbagtech)
- [@carrier4n6](https://twitter.com/carrier4n6) - Brian Carrier, author of Autopsy and the Sleuth Kit
- [@CindyMurph](https://twitter.com/CindyMurph) - Detective & Digital Forensic Examiner
- [@forensikblog](https://twitter.com/forensikblog) - Computer forensic geek
- [@HECFBlog](https://twitter.com/HECFBlog) - SANS Certified Instructor
- [@Hexacorn](https://twitter.com/Hexacorn) - DFIR+Malware
- [@hiddenillusion](https://twitter.com/hiddenillusion)
- [@iamevltwin](https://twitter.com/iamevltwin) - Mac Nerd, Forensic Analyst, Author & Instructor of SANS FOR518
- [@jaredcatkinson](https://twitter.com/jaredcatkinson) - PowerShell Forensics
- [@maridegrazia](https://twitter.com/maridegrazia) - Computer Forensics Examiner
- [@sleuthkit](https://twitter.com/sleuthkit)
- [@williballenthin](https://twitter.com/williballenthin)
- [@XWaysGuide](https://twitter.com/XWaysGuide)

### Blogs

- [thisweekin4n6.wordpress.com](thisweekin4n6.wordpress.com) - Weekly updates for forensics

### Other

- [/r/computerforensics/](https://www.reddit.com/r/computerforensics/) - Subreddit for computer forensics
- [ForensicPosters](https://github.com/Invoke-IR/ForensicPosters) - Posters of file system structures

## Related Awesome Lists

- [Android Security](https://github.com/ashishb/android-security-awesome)
- [AppSec](https://github.com/paragonie/awesome-appsec)
- [Binary](https://github.com/cugu/awesome-binary)
- [CTFs](https://github.com/apsdehal/awesome-ctf)
- [Hacking](https://github.com/carpedm20/awesome-hacking)
- [Honeypots](https://github.com/paralax/awesome-honeypots)
- [Incident-Response](https://github.com/meirwah/awesome-incident-response)
- [Infosec](https://github.com/onlurking/awesome-infosec)
- [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Pentesting](https://github.com/enaqx/awesome-pentest)
- [Security](https://github.com/sbilly/awesome-security)
- [Social Engineering](https://github.com/v2-dev/awesome-social-engineering)
- [YARA](https://github.com/InQuest/awesome-yara)

## [Contributing](CONTRIBUTING.md)

Pull requests and issues with suggestions are welcome!
