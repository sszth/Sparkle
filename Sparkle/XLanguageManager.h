//
//  XLanguageManager.h
//  Sparkle
//
//  Created by hx on 2024/11/11.
//  Copyright © 2024 Sparkle Project. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface XLanguageManager : NSObject
// 公共属性和方法
@property (nonatomic, strong) NSString *currentLanguage;



+ (instancetype)sharedManager;
- (NSBundle *)currentBundle;
- (NSString*)localizedStringForKey:(NSString*)key;


@end

NS_ASSUME_NONNULL_END
