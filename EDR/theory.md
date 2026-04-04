# EDR Hook Analysis – Theory

## Overview
EDR systems monitor API calls by hooking functions in NTDLL.dll.

## Hooking Techniques
- Inline Hooking
- IAT Hooking
- Syscall Interception

## Detection Method
This project compares:
- In-memory function bytes
- Disk-based original bytes

## Syscall Concept
NTDLL functions act as a bridge between user-mode and kernel-mode.

## Limitations
- Kernel-level hooks cannot be detected
- Memory protection may block access

## Conclusion
Modern EDR systems may avoid user-mode hooks and rely on advanced monitoring.