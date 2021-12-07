# jonah

## Project Description Video:

https://youtu.be/dvWrT0H46jM

## Sprint Demos:

### Sprint 1:
https://youtu.be/jXRxDKvv2Ww

### Sprint 2:
https://www.youtube.com/watch?v=jNb1uLlUOnU

### Sprint 3:
https://youtu.be/sUAkF1inqBw

### Sprint 4:
https://youtu.be/-OC-mZm1Z3Y

## Project Owner:

- Shripad J Nadgowda

## Team Members:

- Ryan B Sullivan (ryanbs@bu.edu)
- Qipeng Zou (cloris@bu.edu)
- Jessica Martinez Marquez (jessmtzm@bu.edu)
- Muzammil Hussain (muz@bu.edu)
- Ryte Richard (ryte@bu.edu)

## Vision and Goals Of The Project:

Attestable Container Build will provide a monitoring service to record network connections and file accesses during a container build process. The high level implementation will:

- **Track the whole construction of the container and ensure transparency**
- **Provide reviewable documentation of the build process**
- **Allow for efficient audits of the build process**

Benefits: Observability, Traceability, Compliance
The purpose of jonah is to become the building block of a platform used to verify the container build process. 

## Users/Personas Of The Project:

Attestable Container Build will be used by System Administrators and builders of container-based applications (microservices) who will eventually distribute those container images.  

It targets only System Administrators and builders of containers.

It will not target end users of the built containers; however, end users can use the attested logs to make sure the container was built according to their requirements.

## Scope and Features Of The Project:

- Ensure transparent build processes
  - All network connection will be recorded
  - All file access and modification will be recorded
- Provide reviewable documentation from the build process
  - All data mentioned will be formatted into an attestation form
- Allow for efficient audits of the build process
  - The attestation form will be encrypted with public/private key system
  - The form will be attached to the built container image as an artifact

## Solution Concept:

### Tools to be used:
- Docker: builds container images from Dockerfiles.
- eBPF: run custom code in the Linux kernel. eBPF programs are event-driven and are run when the kernel or an application passes a certain hook point.
- oras: provides a way to attach attestation files to container images
- sha256sum: provides tool to encrypt files and get hashes from existing files to protect file validity
- GnuPG: provides a tool to encrypt files with public/private key pairs to ensure validity of files sent and received
### Possible stretch tools:
- Whaler: reverse engineers a Dockerfile from a container image, reveals files added with the ADD COPY commands and provides miscellaneous information such as user it runs as and environment variables

### Global Architectural Structure Of the Project: 

![CCarchitecture](https://user-images.githubusercontent.com/56104192/134778182-0d789255-acaf-4ca6-8218-026017c2e935.png)

- BPF System hooks are used to capture all relevant information regarding the container build changes within the local system, in this case, network calls and file access and their modifications.
- All captured information will be recorded into the attestation file.
- The attestation file will be encrypted using sha256sum and attached to the corresponding container image using oras, as well as stored locally.
- Any user who wishes to audit the build process can access the attestation file.

### Key Design Decisions:
- BPF System action capture: Linux’s BPF system is an extremely lightweight and powerful system that our design can leverage to capture any system action during the build process. 
- Attachment to build image as an artifact: oras allows us to efficiently link the attestation file to the container image without consuming excess data or processing power. Attaching it to the build image itself also assists in later audits as only one file need be located.
- Public/Private key encryption 


### Acceptance criteria:


### Minimum Viable Product:

Background monitor system able to attach system actions to the finished build image in a formatted attestation file. 

### Stretch goals:

- Connect each system action to its specific line in the Dockerfile
- Detect irregularities in subsequent builds to detect tampering of the Dockerfile
- Use Whaler to reverse engineer the Dockerfile and check any irregularities in it versus the attestation document
- Use sigstore database to store and distribute tamper-free attestation records


## Release Planning:

- Release 1 (Week 5): BPF Hooks

- Release 2 (Week 7): Filter relevant information from collected system data

- Release 3 (Week 9): Set up pre-filtering approach to log docker build information

- Release 4 (Week 11): Expand on eBPF hooks to capture additional data and build a process tree to track all spawned processes by Docker.

- Release 5 (Week 13): Map system events to dockerfile instruction

- Final Release: MVP



