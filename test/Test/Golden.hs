module Test.Golden
  ( goldenTestByteString
  ) where

import Control.Monad.IO.Class ( liftIO )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import GHC.Stack ( HasCallStack, withFrozenCallStack )
import Hedgehog ( Property, property, withTests, (===) )
import Prelude

goldenTestByteString
  :: HasCallStack
  => ByteString
  -> FilePath
  -> Property
goldenTestByteString x path = withFrozenCallStack $ withTests 1 . property $ do
  bs <- liftIO (BS.readFile path)
  x === bs
