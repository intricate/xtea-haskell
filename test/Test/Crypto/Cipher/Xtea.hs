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
prop_golden_example1 :: Property
prop_golden_example1 = goldenTestByteString goldenExample1 "test/golden/xtea/example1/golden.bin"

-- | Test that 'encrypt' output matches the golden example.
prop_golden_example2 :: Property
prop_golden_example2 = goldenTestByteString goldenExample2 "test/golden/xtea/example2/golden.bin"

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

goldenExample1 :: ByteString
goldenExample1 =
  let plaintext = "The quick brown fox jumps over the lazy doglolol"
  in case Xtea.encrypt goldenSymmetricKey plaintext of
    Left err -> error $ "impossible: goldenCiphertext1: " <> show err
    Right x -> x

goldenExample2 :: ByteString
goldenExample2 =
  let plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras vitae faucibus urna. Etiam lectus tortor, eleifend quis ex in, euismod gravida ante. Quisque non eleifend neque. Ut rhoncus lacinia blandit. Maecenas scelerisque faucibus nibh, eu feugiat lorem. Vestibulum pellentesque porta pretium. Sed suscipit mollis tristique. Nam faucibus tellus lobortis justo ultricies, ac maximus lacus cursus. In pharetra tortor neque, quis maximus ex tempor quis. Nullam imperdiet ipsum sit amet urna malesuada, eu laoreet risus rhoncus. Duis volutpat ultrices libero, ut posuere libero tempor vitae. Nullam placerat lectus ipsum, in dictum justo ultricies eget. Donec ac quam placerat, pharetra erat vitae, eleifend est. Quisque eleifend interdum lacus, id varius eros accumsan at. Duis sodales ligula eget massa mollis, ut consectetur arcu molestie. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Curabitur laoreet faucibus elit id scelerisque. Nam fermentum quis neque at feugiat. Vivamus efficitur pellentesque nisl ut rutrum. Aenean ultrices, ipsum nec auctor bibendum, arcu massa sodales ipsum, quis laoreet dolor ex sit amet nunc. Aliquam eu consequat augue, non gravida lorem. Duis sit amet justo at enim sagittis laoreet vitae in enim. Sed felis sem, venenatis ac elit quis, tincidunt dignissim nunc. Sed sit amet felis vitae tellus dictum tincidunt id ut nisi. Suspendisse id tempor enim. Vivamus egestas lorem nec scelerisque venenatis. Phasellus pretium finibus diam in hendrerit. Donec vitae est nisi. Donec at enim tempor, imperdiet sapien sed, vestibulum ligula. Sed eu tellus quis dui dignissim bibendum. Nullam vulputate tellus ac dui sodales, id accumsan ipsum gravida. Sed eu rutrum justo, eu commodo diam. Suspendisse convallis turpis nec odio convallis dignissim. Nunc viverra leo tellus, vel ullamcorper purus sollicitudin vitae. Suspendisse non neque sit amet arcu bibendum tincidunt. Donec congue ex et vulputate convallis. Pellentesque sodales orci id dui maximus convallis. Duis aliquet, magna sit amet viverra aliquet, massa odio interdum diam, sed hendrerit risus dui eget turpis. Sed ipsum erat, cursus nec tempus in, elementum et mi. Nunc eu viverra turpis, non porttitor est. Nullam bibendum dolor eu justo malesuada, nec gravida ante ultrices. Nam non dolor arcu. Pellentesque ac auctor leo. Sed non massa vel lacus luctus porttitor ac quis velit. Ut nec odio vel est porta malesuada ut et nisl. Proin faucibus gravida diam nec sagittis. Curabitur rhoncus tortor sed consequat porttitor. Sed at convallis nulla. Nulla non massa nec arcu egestas facilisis. Maecenas nisl lorem, consequat et venenatis sit amet, porta non augue. Nullam auctor ac nulla et pulvinar. Duis quis velit nec quam pharetra pellentesque. Duis ultricies ante sit amet magna venenatis, id molestie lacus sagittis. Donec in consequat metus, eu tincidunt arcu. Phasellus blandit, magna sit amet tempor posuere, tortor lorem tempor libero, sed consectetur dui est eu tellus. Sed suscipit nisi ut ante ultricies vestibulum. Proin finibus ante non tempus congue. Nunc elit lacus, ullamcorper eu tempus at, maximus a nibh. Fusce sodales mi eu neque efficitur facilisis vel eget orci. Vivamus nec diam sed massa mollis hendrerit. Ut elementum, est ultricies convallis gravida, tortor nunc efficitur purus, ac consectetur purus orci in elit. Nam at diam eu felis aliquet tincidunt non non sapien. Morbi lacinia ligula massa, quis varius neque rutrum vel. Cras tristique quam ac magna semper, id sollicitudin sem vestibulum. Sed pharetra ante et laoreet ornare. Duis a posuere lectus. Donec scelerisque non ante sodales ullamcorper. In sed euismod purus. Vivamus interdum nulla ac justo dictum sagittis. Proin et dui nec neque pellentesque pretium in eu ex. Aenean nunc nibh, elementum ut tortor ac, fringilla vulputate arcu. Suspendisse rhoncus erat id accumsan pulvinar. Morbi dui quam, interdum vel hendrerit a, imperdiet vel tortor. Integer justo velit, commodo eu ante sed, pulvinar vulputate enim. Nam laoreet aliquet nulla vel feugiat. Donec imperdiet massa eget gra"
  in case Xtea.encrypt goldenSymmetricKey plaintext of
    Left err -> error $ "impossible: goldenCiphertext2: " <> show err
    Right x -> x

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

unsafeRenderSymmetricKey :: Xtea.SymmetricKey -> String
unsafeRenderSymmetricKey (Xtea.SymmetricKey k0 k1 k2 k3) =
  "SymmetricKey " <> intercalate " " (map show [k0, k1, k2, k3])
