# Example InSpec Profile

This example shows the implementation of an InSpec profile.


```
name: rocky9-overlay-45drives
title: rocky9-overlay-45drives
maintainer: Mike McPhee <mmcphee@45drives.com>
copyright: 45Drives
copyright_email: mmcphee@45drives.com
license: Apache-2.0
summary: An InSpec Compliance Profile for Rocky Linux 9 based on RHEL9 STIG Baseline
version: 0.0.2
supports:
  #platform: os
  platform-family: redhat

depends:
  - name: redhat-enterprise-linux-9-stig-baseline
    git: https://github.com/mitre/redhat-enterprise-linux-9-stig-baseline.git
    tag: v1.2.3
```
