//
//  VMSA.swift
//  Solarium
//
//  Created by Kien Ho on 11/7/26.
//

import Foundation

class Translation {
    struct ptovEntry {
        let pa: UInt64
        let va: UInt64
        let len: UInt64
    }
    
    var ptovTable = [ptovEntry]()
    var L1Table = [UInt64]()
    var gPhysBase: UInt64 = 0
    var gVirtBase: UInt64 = 0
    var real_phys_size: UInt64 = 0
    let es: eSocket
    let virtSlide: UInt64

    init?(es: eSocket) {
        self.es = es
        self.virtSlide = es.getSlide()
        guard cachePtoV() == true else {
            return nil
        }
        guard cacheL1() == true else {
            return nil
        }
        guard cacheConstants() == true else {
            return nil
        }
    }
    
    private func fmt64(_ v: UInt64) -> String {
        return String(format: "0x%016llX", v)
    }
    
    func cachePtoV() -> Bool {
        print("[VMSA] Caching Physical-to-Virtual table.")
        for i in 0..<8 {
            guard let out = es.get32B(address: virtSlide + koffset.ptov_base + UInt64(24 * i)) else {
                print("[VMSA] Unable to read object, exiting.")
                return false
            }
            let entry = ptovEntry(
                pa: UInt64(out.icmp6_filt.1) << 32 | UInt64(out.icmp6_filt.0),
                va: UInt64(out.icmp6_filt.3) << 32 | UInt64(out.icmp6_filt.2),
                len: UInt64(out.icmp6_filt.5) << 32 | UInt64(out.icmp6_filt.4)
            )
            ptovTable.append(entry)
        }
        return true
    }
    
    func cacheL1() -> Bool {
        print("[VMSA] Caching L1 translation table.")
        guard let cpu_tte = es.get8B(address: virtSlide + koffset.cpu_tte) else {
            print("[VMSA] Unable to read object.")
            return false
        }
        if(cpu_tte >> 48 != 0xffff) {
            print("[VMSA] Invalid kernel address for cpu_tte.")
            return false
        }
        for i in 0..<512 {
            guard let out = es.get32B(address: cpu_tte + UInt64(32 * i)) else {
                print("[VMSA] Unable to read object.")
                return false
            }
            L1Table.append(UInt64(out.icmp6_filt.1) << 32 | UInt64(out.icmp6_filt.0))
            L1Table.append(UInt64(out.icmp6_filt.3) << 32 | UInt64(out.icmp6_filt.2))
            L1Table.append(UInt64(out.icmp6_filt.5) << 32 | UInt64(out.icmp6_filt.4))
            L1Table.append(UInt64(out.icmp6_filt.7) << 32 | UInt64(out.icmp6_filt.6))
        }
        return true
    }
    
    func cacheConstants() -> Bool {
        print("[VMSA] Reading VMSA constants.")
        guard let value = es.get8B(address: virtSlide + koffset.gPhysBase) else {
            print("[VMSA] Unable to read object.")
            return false
        }
        gPhysBase = value
        guard let value = es.get8B(address: virtSlide + koffset.gVirtBase) else {
            print("[VMSA] Unable to read object.")
            return false
        }
        gVirtBase = value
        guard let value = es.get8B(address: virtSlide + koffset.real_phys_size) else {
            print("[VMSA] Unable to read object.")
            return false
        }
        real_phys_size = value
        return true
    }
    
    private func readTableEntry(pa: UInt64) -> UInt64? {
        guard let kva = phystokv(pa: pa) else {
            return nil
        }
        return es.get8B(address: kva)
    }
    
    func phystokv(pa: UInt64) -> UInt64? {
        for entry in ptovTable {
            guard entry.len > 0, pa >= entry.pa else {
                continue
            }

            let offset = pa - entry.pa
            if offset < entry.len {
                let (va, overflow) = entry.va.addingReportingOverflow(offset)
                return overflow ? nil : va
            }
        }

        guard pa >= gPhysBase else {
            return nil
        }

        let offset = pa - gPhysBase
        guard offset < real_phys_size else {
            return nil
        }

        let (va, overflow) = gVirtBase.addingReportingOverflow(offset)
        return overflow ? nil : va
    }
    
    func kvtophys(va: UInt64) -> UInt64? {
        let tableMask: UInt64 = 0x0000_FFFF_FFFF_C000

        let l1Index = Int((va >> 36) & 0x7FF)
        let l2Index = (va >> 25) & 0x7FF
        let l3Index = (va >> 14) & 0x7FF

        guard l1Index < L1Table.count else {
            return nil
        }

        let l1 = L1Table[l1Index]

        guard (l1 & 0x1) != 0 else {
            return nil
        }

        if (l1 & 0x3) == 0x1 {
            let base = l1 & 0x0000_FFF0_0000_0000
            return base | (va & 0xF_FFFF_FFFF)
        }

        guard (l1 & 0x3) == 0x3 else {
            return nil
        }

        let l2TablePA = l1 & tableMask
        let l2EntryPA = l2TablePA + (l2Index * 8)

        guard let l2 = readTableEntry(pa: l2EntryPA) else {
            return nil
        }

        guard (l2 & 0x1) != 0 else {
            return nil
        }

        if (l2 & 0x3) == 0x1 {
            let base = l2 & 0x0000_FFFF_FE00_0000
            return base | (va & 0x1FF_FFFF)
        }

        guard (l2 & 0x3) == 0x3 else {
            return nil
        }

        let l3TablePA = l2 & tableMask
        let l3EntryPA = l3TablePA + (l3Index * 8)

        guard let l3 = readTableEntry(pa: l3EntryPA) else {
            return nil
        }

        guard (l3 & 0x3) == 0x3 else {
            return nil
        }

        let pageBase = l3 & tableMask
        let pageOffset = va & 0x3FFF

        return pageBase | pageOffset
    }
    
    func validateAddr(va: UInt64) -> Bool {
        return kvtophys(va: va) != nil
    }
}
