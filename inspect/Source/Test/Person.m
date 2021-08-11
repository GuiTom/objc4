//
//  Person.m
//  objc-inspect
//
//  Created by 陈超 on 2021/7/6.
//  Copyright © 2021 alchemistxxd. All rights reserved.
//

#import "Person.h"

@implementation Person
-(instancetype)init{
    if(self = [super init]){
        
        [self initSubs];
    }
    return self;
}
-(void)initSubs{
    id c = [self class];
    NSLog(@"abcded:%@",c);
    [self addObserver:self forKeyPath:@"a" options:NSKeyValueObservingOptionNew context:NULL];
    
    id a = [self class];
    Class b = [super class];
   
    NSLog(@"abcded:%@",a);
    NSLog(@"abcd:%@",b);
    
}
-(Class)kvoClass{
    Class b = [super class];
    return b;
}
@end
