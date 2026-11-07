//
//  common.swift
//  Solarium
//
//  Created by Kien Ho on 11/5/26.
//

import Foundation
import Darwin

func allocatePPLpages() -> Bool {
    let MAX_PPL_PAGES = 10000
    let L2_BLOCK_SIZE: UInt = 1 << 25
    let PAGE_SIZE: vm_size_t = 0x4000

    var addresses: [vm_address_t] = []
    var address: vm_address_t = 0
    var givenPPLPages: UInt64 = 0
    
    var data = task_vm_info_data_t()
    var count = mach_msg_type_number_t(mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size))
    var kr = withUnsafeMutablePointer(to: &data) {
        $0.withMemoryRebound(to: integer_t.self, capacity: 1) { info in
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), info, &count)
        }
    }
    if kr != KERN_SUCCESS {
        print("[PPL] Failed to retrieve task info: \(String(cString: mach_error_string(kr)))")
        return false
    }

    let minAddress = UInt64(data.min_address)
    let maxAddress = UInt64(data.max_address)

    while true {
        address += L2_BLOCK_SIZE
        if address < minAddress { continue }
        if address >= maxAddress { break }
        kr = vm_allocate(mach_task_self_, &address, PAGE_SIZE, VM_FLAGS_FIXED)
        if kr == KERN_SUCCESS {
            UnsafeMutableRawPointer(bitPattern: address)!.storeBytes(of: 0x41, as: UInt8.self)
            addresses.append(address)
            givenPPLPages += 1
            if givenPPLPages == MAX_PPL_PAGES { break }
        }
    }

    for i in 0..<givenPPLPages {
        kr = vm_deallocate(mach_task_self_, addresses[Int(i)], PAGE_SIZE)
        if kr != KERN_SUCCESS {
            print("[PPL] Failed to deallocate page \(i): \(String(cString: mach_error_string(kr)))")
            return false
        }
    }
    return true
}

func pages(_ pageCnt: Int) -> vm_size_t {
    return vm_address_t(pageCnt * 0x4000);
}
