//
//  main.c
//  objc-inspect
//
//  Created by 0xxd0 on 2017/12/15.
//  Copyright © 2017年 0xxd0. All rights reserved.
//

/// System Headers
#include <CoreFoundation/CFRunLoop.h>
#include <objc/objc-class.h>
#include <Block.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/// Private Headers
#include "base.h"

//#import <Foundation/Foundation.h>
#import "Person.h"

int main(int argc, const char * argv[]) {
    
    @autoreleasepool {
        Person *object = [[Person alloc] init];
        Class cls = [object kvoClass];
        id a = [[cls alloc] init];
        NSLog(@"%@",a);
    }

    return 0;
}
