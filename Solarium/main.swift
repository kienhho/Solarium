//
//  main.swift
//  Solarium
//
//  Created by Kien Ho on 11/5/26.
//

import Foundation

guard allocatePPLpages() == true else {
    print("[Main] Fail to reserve PPL pages, exiting.")
    exit(1)
}

guard let es = eSocket(count: 2048) else {
    print("[Main] Unable to initialize read object, exiting.")
    exit(1)
}

let kbase = es.getBase()
print("[Main] Kernel base is at 0x\(String(kbase, radix: 16))")






