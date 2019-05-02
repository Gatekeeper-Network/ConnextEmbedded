# Connext Network IoT Client

This repo is intended to host code that enables embedded devices running the Arduino framework to use the Connext Network protocol. This is PoC software. In order to use this package you will need to add your own key storage and managament facillities, as well as state management and signing procedures. These will be included in upcoming GKOS

Known Bugs/Pitfalls
  - Not (necessarily) thread safe
# Client Features

  - Authentication with Hub
  - Device Token & Wei Deposit (on chain)
  - Collateralization of Tokens & Wei with Hub (Custodial payments)
  - Polling for new payments from Hub. 

### Prerequisites
Change CMAuth.ts for the Connext Hub. (will post patch soon)
### Installation

Installation will depend on your target hardware, toolchain and IDE but basic procedures to add Arduino libraries apply, ie GCC should know about the arduino includes. You will also have to add Web3 and ArduinoJson libraries in your includes.

```sh
\\see header
#include <Arduino.h>
#include <Web3.h> 
#include <ArduinoJson.h> 
```

### Compatible Devices
Tested on multiple ESP32 boards, inside the arduino environment (on top of FreeRTOS)

### Docker
Dillinger is very easy to install and deploy in a Docker container.

By default, the Docker will expose port 8080, so change this within the Dockerfile if necessary. When ready, simply use the Dockerfile to build the image.



License
----

MIT


