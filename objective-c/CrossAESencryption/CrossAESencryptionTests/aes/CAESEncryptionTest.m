//
//  CAESEncryptionTest.m
//  CrossAESencryption
//
//  Created by Georgi Lambov on 10/16/13.
//  Copyright (c) 2013 Georgi Lambov. All rights reserved.
//

#import "CAESEncryptionTest.h"

@implementation CAESEncryptionTest

- (void)setUp {
    [super setUp];
    key = @"MySecretKeyMustBe32CharactersLng";
}

- (void)tearDown {
    [super tearDown];
}

- (void)testFBEncryptorDataDecryptedOnServerSide {
    NSString *encoded = @"{\"progress\": [], \"goods\": {\"coins\": 100000, \"diamonds\": 100000}, \"inventory\": {\"characters\": [], \"costumes\": []}}";
    NSString *cipher = [FBEncryptorAES encryptBase64String:encoded keyString:key separateLines:FALSE];
    
    NSLog(@"FBEncryptorAES %@", cipher);
    NSString *expectedCipher = @"9ufo4Hw8QHddnaBf6YRSrzsRTsEPOf2XlYM0LEWROkT1FNi5TAd+ickmBPhsOy3Oibjb3O7pswBEq+TRvdr1ArMGybkTQoXuzain7WPzjURM40lBaNGWKNiV63i4Csphz9E9U0CES/p03mVpX44xwM5f/4fAC7BRn7eKuLlBkJ8=";
    
    STAssertEqualObjects(cipher, expectedCipher, @"both chipers should be equal");
}

- (void)testEncryptionWithSingleBlockOnServerSide {
    NSString *encoded = @"aaaaaaaaaaaaaaa";
    NSString *cipher = [FBEncryptorAES encryptBase64String:encoded keyString:key separateLines:FALSE];
    NSLog(@"FBEncryptorAES single block %@", cipher);

    NSString *expectedCipher = @"ENMRNjI1Z1OZoG1H6jdhjQ==";
    
    STAssertEqualObjects(cipher, expectedCipher, @"both chipers should be equal");
    
    NSString *decrypted = [FBEncryptorAES decryptBase64String:cipher keyString:key];
    STAssertEqualObjects(encoded, decrypted, @"decrypted value should be a*");
}

- (void)testFBEncryptorDataEncryptedOnServerSide {
    NSString *encrypted = @"BiIm9m5vLXyHpTC7uZcbow==";
    NSString *decrypted = [FBEncryptorAES decryptBase64String:encrypted keyString:key];
    STAssertEqualObjects(@"a", decrypted, @"decrypted value should be a");
}

@end
