{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Cipher.Xtea
  ( tests
  ) where

import qualified Crypto.Cipher.Xtea as Xtea
import Data.ByteString ( ByteString )
import Data.List ( intercalate )
import Hedgehog
  ( Gen
  , Property
  , checkParallel
  , discover
  , forAll
  , forAllWith
  , property
  , tripping
  )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Golden ( goldenTestByteString )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'encryptBlock' and 'decryptBlock' round trip.
prop_roundTrip_encryptBlockDecryptBlock :: Property
prop_roundTrip_encryptBlockDecryptBlock = property $ do
  k <- forAllWith unsafeRenderSymmetricKey genSymmetricKey
  x <- forAll $ (,) <$> Gen.word32 Range.constantBounded <*> Gen.word32 Range.constantBounded
  tripping x (Xtea.encryptBlock k) (Just . Xtea.decryptBlock k)

-- | Test that 'encrypt' and 'decrypt' round trip.
prop_roundTrip_encryptDecrypt :: Property
prop_roundTrip_encryptDecrypt = property $ do
  k <- forAllWith unsafeRenderSymmetricKey genSymmetricKey

  -- Generate a 'ByteString' whose length is divisible by 8.
  let maxLen = 2048 -- Arbitrarily choosing 2048 as the max length.
  multiple <- forAll $ Gen.int (Range.constant 1 (fst $ maxLen `divMod` 8))
  x <- forAll $ Gen.bytes (Range.singleton $ multiple * 8)

  tripping x (unsafeEncrypt k) (Xtea.decrypt k)
  where
    unsafeEncrypt :: Xtea.SymmetricKey -> ByteString -> ByteString
    unsafeEncrypt k x =
      case Xtea.encrypt k x of
        Left err -> error $ "impossible: could not encrypt: " <> show err
        Right encrypted -> encrypted

-- | Test that 'encrypt' output matches the golden example.
prop_golden_encrypt :: Property
prop_golden_encrypt = goldenTestByteString goldenCiphertext "test/golden/xtea/golden.bin"

------------------------------------------------------------------------------
-- Generators
------------------------------------------------------------------------------

genSymmetricKey :: Gen Xtea.SymmetricKey
genSymmetricKey =
  Xtea.SymmetricKey
    <$> Gen.word32 Range.constantBounded
    <*> Gen.word32 Range.constantBounded
    <*> Gen.word32 Range.constantBounded
    <*> Gen.word32 Range.constantBounded

------------------------------------------------------------------------------
-- Golden examples
------------------------------------------------------------------------------

goldenSymmetricKey :: Xtea.SymmetricKey
goldenSymmetricKey = Xtea.SymmetricKey 0x41414141 0x42424242 0x43434343 0x44444444

goldenPlaintext :: ByteString
goldenPlaintext = "The quick brown fox jumps over the lazy doglolol"

goldenCiphertext :: ByteString
goldenCiphertext =
  case Xtea.encrypt goldenSymmetricKey goldenPlaintext of
    Left err -> error $ "impossible: goldenEncryptedByteString: " <> show err
    Right x -> x

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

unsafeRenderSymmetricKey :: Xtea.SymmetricKey -> String
unsafeRenderSymmetricKey (Xtea.SymmetricKey k0 k1 k2 k3) =
  "SymmetricKey " <> intercalate " " (map show [k0, k1, k2, k3])
