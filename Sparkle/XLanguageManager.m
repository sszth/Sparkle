//
//  XLanguageManager.m
//  Sparkle
//
//  Created by hx on 2024/11/11.
//  Copyright © 2024 Sparkle Project. All rights reserved.
//

#import "XLanguageManager.h"

@implementation XLanguageManager

static XLanguageManager *sharedManager = nil;

+ (instancetype)sharedManager {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedManager = [[self alloc] init];
    });
    return sharedManager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        // 初始化代码，例如默认语言设置
        _currentLanguage = @"en"; // 默认语言为英语
    }
    return self;
}

- (NSBundle *)currentBundle {
    // 获取新语言的 Bundle
    NSString *bundlePath = [[NSBundle mainBundle] pathForResource:_currentLanguage ofType:@"lproj"];
    if (bundlePath) {
        NSBundle *newBundle = [NSBundle bundleWithPath:bundlePath];
        if (newBundle) {
            return newBundle;
        }
    }

    return [NSBundle mainBundle];
}

- (NSString *)localizedStringForKey:(NSString *)key {
    return [[self currentBundle] localizedStringForKey:key value:nil table:nil];
}

    
//
//- (NSString *)currentLanguage {
//    return _currentLanguage;
//}
//
//- (void)setLanguage:(NSString *)languageCode {
//    // 设置新的语言代码
//    _currentLanguage = [languageCode copy];
//    
//    // 可以在这里添加更多的处理，比如通知应用更新语言
//    // 发送通知
//    [[NSNotificationCenter defaultCenter] postNotificationName:@"LanguageChanged" object:nil];
//}

@end
