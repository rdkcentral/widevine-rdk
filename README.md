# widevine-rdk
Common OCDM Widevine Mediasession

This repo is created for RDKE layer architecure stack.

The Common OCDM implementation is coupled with two components.
1. Common rdk-adapter which pass the encrypted content to OCDM Mediasession to decrypt it. 
2. gst-svp-ext component which implements the SoC specific implementation for Secure Video Path support.
