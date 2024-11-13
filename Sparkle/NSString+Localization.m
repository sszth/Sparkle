//
//  NSString+Localization.m
//  Sparkle
//
//  Created by hx on 2024/11/13.
//  Copyright © 2024 Sparkle Project. All rights reserved.
//

#import "NSString+Localization.h"
#import "XLanguageManager.h"

@implementation NSString (Localization)

- (NSString *)localized {
    return [[XLanguageManager sharedManager] localizedStringForKey:self];
}

@end
