# rdk-wifi-hal

Repository contains wifi functionality state machines and packet processing, examples include EasyConnect packet processing, Passpoint packet processing.

## Overview

The RDK WiFi HAL (Hardware Abstraction Layer) provides a standardized interface for WiFi operations in RDK-based devices. This repository includes:

- WiFi state machine implementations
- EasyConnect (DPP - Device Provisioning Protocol) packet processing
- Passpoint (Hotspot 2.0) packet processing
- NetLink (nl80211) driver interfaces
- ANQP (Access Network Query Protocol) handling
- WNM-RRM (Wireless Network Management/Radio Resource Management)

## Building

This project uses GNU Autotools for building:

```bash
./configure
make
```

For platform-specific builds, refer to the platform directories under `platform/`.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

**Important:** 
- You must sign the RDK Contributor License Agreement (CLA) before your contributions can be accepted
- If you're experiencing Git authentication issues or working with multiple GitHub accounts, see our [Git Setup Guide](GIT_SETUP.md)

## Documentation

- [Contributing Guidelines](CONTRIBUTING.md)
- [Git Setup and Credential Management](GIT_SETUP.md)
- [Code Style Guide](CODE_STYLE.md)
- [hostapd/wpa_supplicant License Info](README_hostapd)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
