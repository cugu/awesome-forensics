# Awesome Forensics [![Link Status](https://github.com/cugu/awesome-forensics/workflows/CI/badge.svg)](https://github.com/cugu/awesome-forensics)

Curated list of awesome **free** (mostly open source) forensic analysis tools and resources.

- Awesome Forensics
  - [Collections](#collections)
  - [Tools](#tools)
    - [Distributions](#distributions)
    - [Frameworks](#frameworks)
    - [Live Forensics](#live-forensics)
    - [IOC Scanner](#ioc-scanner)
    - [Acquisition](#acquisition)
    - [Imaging](#imaging)
    - [Carving](#carving)
    - [Memory Forensics](#memory-forensics)
    - [Network Forensics](#network-forensics)
    - [Windows Artifacts](#windows-artifacts)
      - [NTFS/MFT Processing](#ntfsmft-processing)
    - [OS X Forensics](#os-x-forensics)
    - [Mobile Forensics](#mobile-forensics)
    - [Docker Forensics](#docker-forensics)
    - [Internet Artifacts](#internet-artifacts)
    - [Timeline Analysis](#timeline-analysis)
    - [Disk image handling](#disk-image-handling)
    - [Decryption](#decryption)
    - [Management](#management)
    - [Picture Analysis](#picture-analysis)
    - [Metadata Forensics](#metadata-forensics)
    - [Steganography](#steganography)
  - [Learn Forensics](#learn-forensics)
    - [CTFs and Challenges](#ctfs-and-challenges)
  - [Resources](#resources)
    - [Web](#web)
    - [Blogs](#blogs)
    - [Books](#books)
    - [File System Corpora](#file-system-corpora)
    - [Other](#other)
    - [Labs](#labs)
  - [Related Awesome Lists](#related-awesome-lists)
  - [Contributing](#contributing)

---

## Collections

- [AboutDFIR – The Definitive Compendium Project](https://aboutdfir.com) - Collection of forensic resources for learning and research. Offers lists of certifications, books, blogs, challenges and more
- :star: [ForensicArtifacts.com Artifact Repository](https://github.com/ForensicArtifacts/artifacts) - Machine-readable knowledge base of forensic artifacts

## Tools

- [Forensics tools on Wikipedia](https://en.wikipedia.org/wiki/List_of_digital_forensics_tools)
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md)

### Distributions

- [bitscout](https://github.com/vitaly-kamluk/bitscout) - LiveCD/LiveUSB for remote forensic acquisition and analysis
- [Remnux](https://remnux.org/) - Distro for reverse-engineering and analyzing malicious software
- [SANS Investigative Forensics Toolkit (sift)](https://github.com/teamdfir/sift) - Linux distribution for forensic analysis
- [Tsurugi Linux](https://tsurugi-linux.org/) - Linux distribution for forensic analysis
- [WinFE](https://www.winfe.net/home) - Windows Forensics enviroment

### Frameworks

- :star:[Autopsy](http://www.sleuthkit.org/autopsy/) - SleuthKit GUI
- [dexter](https://github.com/coinbase/dexter) - Dexter is a forensics acquisition framework designed to be extensible and secure
- [dff](https://github.com/arxsys/dff) - Forensic framework
- [Dissect](https://github.com/fox-it/dissect) - Dissect is a digital forensics & incident response framework and toolset that allows you to quickly access and analyse forensic artefacts from various disk and file formats, developed by Fox-IT (part of NCC Group).
- [hashlookup-forensic-analyser](https://github.com/hashlookup/hashlookup-forensic-analyser) - A tool to analyse files from a forensic acquisition to find known/unknown hashes from [hashlookup](https://www.circl.lu/services/hashlookup/) API or using a local Bloom filter.
- [IntelMQ](https://github.com/certtools/intelmq) - IntelMQ collects and processes security feeds
- [Kuiper](https://github.com/DFIRKuiper/Kuiper) - Digital Investigation Platform
- [Laika BOSS](https://github.com/lmco/laikaboss) - Laika is an object scanner and intrusion detection system
- [OpenRelik](https://openrelik.org/) - Forensic platform to store file artifacts and run workflows
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - PowerForensics is a framework for live disk forensic analysis
- [TAPIR](https://github.com/tap-ir/tapir) - TAPIR (Trustable Artifacts Parser for Incident Response) is a multi-user, client/server, incident response framework
- :star: [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) - Tools for low level forensic analysis
- [turbinia](https://github.com/google/turbinia) - Turbinia is an open-source framework for deploying, managing, and running forensic workloads on cloud platforms
- [IPED - Indexador e Processador de Evidências Digitais](https://github.com/sepinf-inc/IPED) - Brazilian Federal Police Tool for Forensic Investigations
- [Wombat Forensics](https://github.com/pjrinaldi/wombatforensics) - Forensic GUI tool

### Live Forensics

- [grr](https://github.com/google/grr) - GRR Rapid Response: remote live forensics for incident response
- [Linux Expl0rer](https://github.com/intezer/linux-explorer) - Easy-to-use live forensics toolbox for Linux endpoints written in Python & Flask
- [mig](https://github.com/mozilla/mig) - Distributed & real time digital forensics at the speed of the cloud
- [osquery](https://github.com/osquery/osquery) - SQL powered operating system analytics
- [POFR](https://github.com/gmagklaras/pofr) - The Penguin OS Flight Recorder collects, stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System.
- [UAC](https://github.com/tclahr/uac) - UAC (Unix-like Artifacts Collector) is a Live Response collection script for Incident Response that makes use of native binaries and tools to automate the collection of AIX, Android, ESXi, FreeBSD, Linux, macOS, NetBSD, NetScaler, OpenBSD and Solaris systems artifacts.

### IOC Scanner

- [Fastfinder](https://github.com/codeyourweb/fastfinder) - Fast customisable cross-platform suspicious file finder. Supports md5/sha1/sha256 hashes, literal/wildcard strings, regular expressions and YARA rules
- [Fenrir](https://github.com/Neo23x0/Fenrir) - Simple Bash IOC Scanner
- [Loki](https://github.com/Neo23x0/Loki) - Simple IOC and Incident Response Scanner
- [Redline](https://fireeye.market/apps/211364) - Free endpoint security tool from FireEye
- [THOR Lite](https://www.nextron-systems.com/thor-lite/) - Free IOC and YARA Scanner
- [recon](https://github.com/rusty-ferris-club/recon) - Performance oriented file finder with support for SQL querying, index and analyze file metadata with support for YARA.

### Acquisition

- [Acquire](https://github.com/fox-it/acquire) - Acquire is a tool to quickly gather forensic artifacts from disk images or a live system into a lightweight container
- [artifactcollector](https://github.com/forensicanalysis/artifactcollector) - A customizable agent to collect forensic artifacts on any Windows, macOS or Linux system
- [ArtifactExtractor](https://github.com/Silv3rHorn/ArtifactExtractor) - Extract common Windows artifacts from source images and VSCs
- [AVML](https://github.com/microsoft/avml) - A portable volatile memory acquisition tool for Linux
- [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer) - Volatile Memory Acquisition Tool
- [DFIR ORC](https://dfir-orc.github.io/) - Forensics artefact collection tool for systems running Microsoft Windows
- [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - Collect artifacts on windows
- [FireEye Memoryze](https://fireeye.market/apps/211368) - A free memory forensic software
- [FIT](https://github.com/fit-project/fit) - Forensic acquisition of web pages, emails, social media, etc.
- [ForensicMiner](https://github.com/securityjoes/ForensicMiner) - A PowerShell-based DFIR automation tool, for artifact and evidence collection on Windows machines.
- [Fuji](https://github.com/Lazza/Fuji/) - MacOS forensic acquisition made simple. It creates full file system copies or targeted collection of Mac computers.
- [LiME](https://github.com/504ensicsLabs/LiME) - Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, formerly called DMD
- [Magnet RAM Capture / DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/) - A free imaging tool designed to capture the physical memory
- [SPECTR3](https://github.com/alpine-sec/SPECTR3) - Acquire, triage and investigate remote evidence via portable iSCSI readonly access
- [UFADE](https://github.com/prosch88/UFADE) - Extract files from iOS devices on Linux and MacOS. Mostly a wrapper for pymobiledevice3. Creates iTunes-style backups and advanced logical backups.
- [unix_collector](https://github.com/op7ic/unix_collector) - A live forensic collection script for UNIX-like systems as a single script.
- [Velociraptor](https://github.com/Velocidex/velociraptor) - Velociraptor is a tool for collecting host based state information using Velocidex Query Language (VQL) queries
- [WinTriage](https://www.securizame.com/wintriage-the-triage-tool-for-windows-dfirers/) - Wintriage is a live response tool that extracts Windows artifacts. It must be executed with local or domain administrator privileges and recommended to be done from an external drive.

### Imaging

- [dc3dd](https://sourceforge.net/projects/dc3dd/) - Improved version of dd
- [dcfldd](https://sourceforge.net/projects/dcfldd/) - Different improved version of dd (this version has some bugs!, another version is on github [adulau/dcfldd](https://github.com/adulau/dcfldd))
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager) - Free imageing tool for windows
- :star: [Guymager](https://sourceforge.net/projects/guymager/) - Open source version for disk imageing on linux systems
- [4n6pi](https://github.com/plonxyz/4n6pi) - Forensic disk imager, designed to run on a Raspberry Pi, powered by libewf

### Carving

- [bstrings](https://github.com/EricZimmerman/bstrings) - Improved strings utility
- [bulk_extractor](https://github.com/simsong/bulk_extractor) - Extracts information such as email addresses, creditcard numbers and histrograms from disk images
- [floss](https://github.com/mandiant/flare-floss) - Static analysis tool to automatically deobfuscate strings from malware binaries
- :star: [photorec](https://www.cgsecurity.org/wiki/PhotoRec) - File carving tool
- [swap_digger](https://github.com/sevagas/swap_digger) - A bash script used to automate Linux swap analysis, automating swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, etc.

### Memory Forensics

- [inVtero.net](https://github.com/ShaneK2/inVtero.net) - High speed memory analysis framework
  developed in .NET supports all Windows x64, includes code integrity and write support
- [KeeFarce](https://github.com/denandz/KeeFarce) - Extract KeePass passwords from memory
- [MemProcFS](https://github.com/ufrisk/MemProcFS) - An easy and convenient way of accessing physical memory as files a virtual file system.
- [Rekall](https://github.com/google/rekall) - Memory Forensic Framework
- [volatility](https://github.com/volatilityfoundation/volatility) - The memory forensic framework
- [VolUtility](https://github.com/kevthehermit/VolUtility) - Web App for Volatility framework

### Network Forensics

- [Kismet](https://github.com/kismetwireless/kismet) - A passive wireless sniffer
- [NetworkMiner](https://www.netresec.com/?page=Networkminer) - Network Forensic Analysis Tool
- [Squey](https://squey.org) - Logs/PCAP visualization software designed to detect anomalies and weak signals in large amounts of data.
- :star: [WireShark](https://www.wireshark.org/) - A network protocol analyzer

### Windows Artifacts

- [Beagle](https://github.com/yampelo/beagle) -  Transform data sources and logs into graphs
- [Blauhaunt](https://github.com/cgosec/Blauhaunt) - A tool collection for filtering and visualizing logon events
- [FRED](https://www.pinguin.lu/fred) - Cross-platform microsoft registry hive editor
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) - A a sigma-based threat hunting and fast forensics timeline generator for Windows event logs.
- [LastActivityView](https://www.nirsoft.net/utils/computer_activity_view.html) - LastActivityView by Nirsoftis a tool for Windows operating system that collects information from various sources on a running system, and displays a log of actions made by the user and events occurred on this computer. 
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Investigate malicious Windows logon by visualizing and analyzing Windows event log
- [PyShadow](https://github.com/alicangnll/pyshadow) - A library for Windows to read shadow copies, delete shadow copies, create symbolic links to shadow copies, and create shadow copies
- [python-evt](https://github.com/williballenthin/python-evt) - Pure Python parser for classic Windows Event Log files (.evt)
- [RegRipper3.0](https://github.com/keydet89/RegRipper3.0) - RegRipper is an open source Perl tool for parsing the Registry and presenting it for analysis
- [RegRippy](https://github.com/airbus-cert/regrippy) - A framework for reading and extracting useful forensics data from Windows registry hives

#### NTFS/MFT Processing

- [MFT-Parsers](http://az4n6.blogspot.com/2015/09/whos-your-master-mft-parsers-reviewed.html) - Comparison of MFT-Parsers
- [MFTEcmd](https://binaryforay.blogspot.com/2018/06/introducing-mftecmd.html) - MFT Parser by Eric Zimmerman
- [MFTExtractor](https://github.com/aarsakian/MFTExtractor) - MFT-Parser
- [MFTMactime](https://github.com/kero99/mftmactime) - MFT and USN parser that allows direct extraction in filesystem timeline format (mactime), dump all resident files in the MFT in their original folder structure and run yara rules over them all.
- [NTFS journal parser](http://strozfriedberg.github.io/ntfs-linker/)
- [NTFS USN Journal parser](https://github.com/PoorBillionaire/USN-Journal-Parser)
- [RecuperaBit](https://github.com/Lazza/RecuperaBit) - Reconstruct and recover NTFS data
- [python-ntfs](https://github.com/williballenthin/python-ntfs) - NTFS analysis

### OS X Forensics

- [APFS Fuse](https://github.com/sgan81/apfs-fuse) - A read-only FUSE driver for the new Apple File System
- [mac_apt (macOS Artifact Parsing Tool)](https://github.com/ydkhatri/mac_apt) - Extracts forensic artifacts from disk images or live machines
- [MacLocationsScraper](https://github.com/mac4n6/Mac-Locations-Scraper) - Dump the contents of the location database files on iOS and macOS
- [macMRUParser](https://github.com/mac4n6/macMRU-Parser) - Python script to parse the Most Recently Used (MRU) plist files on macOS into a more human friendly format
- [OSXAuditor](https://github.com/jipegit/OSXAuditor)
- [OSX Collect](https://github.com/Yelp/osxcollector)

### Mobile Forensics

- [Andriller](https://github.com/den4uk/andriller) - A software utility with a collection of forensic tools for smartphones
- [ALEAPP](https://github.com/abrignoni/ALEAPP) - An Android Logs Events and Protobuf Parser
- [ArtEx](https://www.doubleblak.com/index.php) - Artifact Examiner for iOS Full File System extractions
- [iLEAPP](https://github.com/abrignoni/iLEAPP) - An iOS Logs, Events, And Plists Parser
- [iOS Frequent Locations Dumper](https://github.com/mac4n6/iOS-Frequent-Locations-Dumper) - Dump the contents of the StateModel#.archive files located in /private/var/mobile/Library/Caches/com.apple.routined/
- [MEAT](https://github.com/jfarley248/MEAT) - Perform different kinds of acquisitions on iOS devices
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - An automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
- [OpenBackupExtractor](https://github.com/vgmoose/OpenBackupExtractor) - An app for extracting data from iPhone and iPad backups.


### Docker Forensics

- [dof (Docker Forensics Toolkit)](https://github.com/docker-forensics-toolkit/toolkit) - Extracts and interprets forensic artifacts from disk images of Docker Host systems
- [Docker Explorer](https://github.com/google/docker-explorer) Extracts and interprets forensic artifacts from disk images of Docker Host systems

### Internet Artifacts

- [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) - A small utility that reads the cache folder of Google Chrome Web browser, and displays the list of all files currently stored in the cache
- [chrome-url-dumper](https://github.com/eLoopWoo/chrome-url-dumper) - Dump all local stored infromation collected by Chrome
- [hindsight](https://github.com/obsidianforensics/hindsight) - Internet history forensics for Google Chrome/Chromium
- [IE10Analyzer](https://github.com/moaistory/IE10Analyzer) - This tool can parse normal records and recover deleted records in WebCacheV01.dat.
- [unfurl](https://github.com/obsidianforensics/unfurl) - Extract and visualize data from URLs
- [WinSearchDBAnalyzer](https://github.com/moaistory/WinSearchDBAnalyzer) - This tool can parse normal records and recover deleted records in Windows.edb.

### Timeline Analysis

- [DFTimewolf](https://github.com/log2timeline/dftimewolf) - Framework for orchestrating forensic collection, processing and data export using GRR and Rekall
- :star: [plaso](https://github.com/log2timeline/plaso) - Extract timestamps from various files and aggregate them
- [Timeline Explorer](https://binaryforay.blogspot.com/2017/04/introducing-timeline-explorer-v0400.html) - Timeline Analysis tool for CSV and Excel files. Built for SANS FOR508 students
- [timeliner](https://github.com/airbus-cert/timeliner) - A rewrite of mactime, a bodyfile reader
- [timesketch](https://github.com/google/timesketch) - Collaborative forensic timeline analysis

### Disk image handling

- [Disk Arbitrator](https://github.com/aburgh/Disk-Arbitrator) - A Mac OS X forensic utility designed to help the user ensure correct forensic procedures are followed during imaging of a disk device
- [imagemounter](https://github.com/ralphje/imagemounter) - Command line utility and Python package to ease the (un)mounting of forensic disk images
- [libewf](https://github.com/libyal/libewf) - Libewf is a library and some tools to access the Expert Witness Compression Format (EWF, E01)
- [PancakeViewer](https://github.com/forensicmatt/PancakeViewer) - Disk image viewer based in dfvfs, similar to the FTK Imager viewer
- [xmount](https://www.pinguin.lu/xmount) - Convert between different disk image formats

### Decryption

- [hashcat](https://hashcat.net/hashcat/) - Fast password cracker with GPU support
- [John the Ripper](https://www.openwall.com/john/) - Password cracker

### Management

- [Catalyst](https://github.com/SecurityBrewery/catalyst) - Catalyst is an open source security automation and ticket system
- [dfirtrack](https://github.com/dfirtrack/dfirtrack) - Digital Forensics and Incident Response Tracking application, track systems
- [Incidents](https://github.com/veeral-patel/incidents) - Web application for organizing non-trivial security investigations. Built on the idea that incidents are trees of tickets, where some tickets are leads
- [iris](https://github.com/dfir-iris/iris-web) - Collaborative Incident Response platform

### Picture Analysis

- [Ghiro](https://github.com/Ghirensics/ghiro) - A fully automated tool designed to run forensics analysis over a massive amount of images
- [sherloq](https://github.com/GuidoBartoli/sherloq) - An open-source digital photographic image forensic toolset

### Metadata Forensics

- [ExifTool](https://exiftool.org/) by Phil Harvey
- [FOCA](https://github.com/ElevenPaths/FOCA) - FOCA is a tool used mainly to find metadata and hidden information in the documents

### Steganography

- [Sonicvisualizer](https://www.sonicvisualiser.org)
- [Steghide](https://github.com/StegHigh/steghide) - is a steganography program that hides data in various kinds of image and audio files
- [Wavsteg](https://github.com/samolds/wavsteg) - is a steganography program that hides data in various kinds of image and audio files
- [Zsteg](https://github.com/zed-0xff/zsteg) - A steganographic coder for WAV files

## Learn Forensics

- [Forensic challenges](https://www.amanhardikar.com/mindmaps/ForensicChallenges.html) - Mindmap of forensic challenges
- [OpenLearn](https://www.open.edu/openlearn/science-maths-technology/digital-forensics/content-section-0?active-tab=description-tab) - Digital forensic course

### CTFs and Challenges

- [BelkaCTF](https://belkasoft.com/ctf) - CTFs by Belkasoft
- [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/?type=ctf) 
- [DefCon CTFs](https://archive.ooo) - archive of DEF CON CTF challenges.
- [Forensics CTFs](https://github.com/apsdehal/awesome-ctf/blob/master/README.md#forensics)
- [MagnetForensics CTF Challenge](https://www.magnetforensics.com/blog/magnet-weekly-ctf-challenge/)
- [MalwareTech Challenges](https://www.malwaretech.com/challenges)
- [MemLabs](https://github.com/stuxnet999/MemLabs)
- [NW3C Chanllenges](https://nw3.ctfd.io)
- [Precision Widgets of North Dakota Intrusion](https://betweentwodfirns.blogspot.com/2017/11/dfir-ctf-precision-widgets-of-north.html)
- [ReverseEngineering Challenges](https://challenges.re)

## Resources

### Web

- [ForensicsFocus](https://www.forensicfocus.com/)
- [SANS Digital Forensics](https://www.sans.org/digital-forensics-incident-response/)

### Blogs

- [Netresec](https://www.netresec.com/index.ashx?page=Blog)
- [SANS Forensics Blog](https://www.sans.org/blog/?focus-area=digital-forensics)
- [SecurityAffairs](https://securityaffairs.com/) - blog by Pierluigi Paganini
- [This Week In 4n6](https://thisweekin4n6.com/) - Weekly updates for forensics
- [Zena Forensics](https://blog.digital-forensics.it/)

### Books

*more at [Recommended Readings](http://dfir.org/?q=node/8) by Andrew Case*

- [Network Forensics: Tracking Hackers through Cyberspace](https://www.pearson.com/en-us/subject-catalog/p/Davidoff-Network-Forensics-Tracking-Hackers-through-Cyberspace/P200000009228) - Learn to recognize hackers’ tracks and uncover network-based evidence
- [The Art of Memory Forensics](https://www.memoryanalysis.net/amf) - Detecting Malware and Threats in Windows, Linux, and Mac Memory
- [The Practice of Network Security Monitoring](https://nostarch.com/nsm) - Understanding Incident Detection and Response

### File System Corpora

- [Digital Forensic Challenge Images](https://www.ashemery.com/dfir.html) - Two DFIR challenges with images
- [Digital Forensics Tool Testing Images](https://sourceforge.net/projects/dftt/)
- [The CFReDS Project](https://cfreds.nist.gov)
  - [Hacking Case (4.5 GB NTFS Image)](https://cfreds.nist.gov/Hacking_Case.html)

### Other

- [/r/computerforensics/](https://www.reddit.com/r/computerforensics/) - Subreddit for computer forensics
- [ForensicPosters](https://github.com/Invoke-IR/ForensicPosters) - Posters of file system structures
- [SANS Posters](https://www.sans.org/posters/) - Free posters provided by SANS

### Labs

- [BlueTeam.Lab](https://github.com/op7ic/BlueTeam.Lab) - Blue Team detection lab created with Terraform and Ansible in Azure.

## Related Awesome Lists

- [Android Security](https://github.com/ashishb/android-security-awesome)
- [AppSec](https://github.com/paragonie/awesome-appsec)
- [CTFs](https://github.com/apsdehal/awesome-ctf)
- [Hacking](https://github.com/carpedm20/awesome-hacking)
- [Honeypots](https://github.com/paralax/awesome-honeypots)
- [Incident-Response](https://github.com/meirwah/awesome-incident-response)
- [Infosec](https://github.com/onlurking/awesome-infosec)
- [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Pentesting](https://github.com/enaqx/awesome-pentest)
- [Security](https://github.com/sbilly/awesome-security)
- [Social Engineering](https://github.com/giuliacassara/awesome-social-engineering)
- [YARA](https://github.com/InQuest/awesome-yara)

## [Contributing](CONTRIBUTING.md)

Pull requests and issues with suggestions are welcome!
